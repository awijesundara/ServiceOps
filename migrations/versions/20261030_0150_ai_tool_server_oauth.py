"""OAuth client-credentials sign-in for connected MCP servers.

Adds ai_tool_server.auth_mode ("header" or "client_credentials"), token_url,
client_id and token_scope. Existing servers keep "header". Expand only.

Revision ID: 20261030_0150
Revises: 20261030_0149
"""
from alembic import op
import sqlalchemy as sa

revision = "20261030_0150"
down_revision = "20261030_0149"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

COLUMNS = (
    ("auth_mode", 20, "header"),
    ("token_url", 500, ""),
    ("client_id", 200, ""),
    ("token_scope", 300, ""),
)


def upgrade():
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("ai_tool_server")}
    for name, length, default in COLUMNS:
        if name not in existing:  # a new database's baseline already created it from the models
            op.add_column("ai_tool_server", sa.Column(name, sa.String(length=length), nullable=False, server_default=default))


def downgrade():
    for name, _length, _default in reversed(COLUMNS):
        op.drop_column("ai_tool_server", name)
