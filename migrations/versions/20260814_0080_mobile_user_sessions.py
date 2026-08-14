"""User-authenticated mobile sessions and client attribution.

Revision ID: 20260814_0080
Revises: 20260813_0079
"""
from alembic import op
import sqlalchemy as sa

revision = "20260814_0080"
down_revision = "20260813_0079"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("api_client")}
    additions = {
        "client_kind": sa.Column("client_kind", sa.String(20), nullable=False, server_default="integration"),
        "refresh_token_hash": sa.Column("refresh_token_hash", sa.String(64)),
        "access_expires_at": sa.Column("access_expires_at", sa.DateTime(timezone=True)),
        "refresh_expires_at": sa.Column("refresh_expires_at", sa.DateTime(timezone=True)),
        "app_version": sa.Column("app_version", sa.String(40)),
        "app_build": sa.Column("app_build", sa.String(40)),
        "platform": sa.Column("platform", sa.String(40)),
        "device_model": sa.Column("device_model", sa.String(120)),
    }
    for name, column in additions.items():
        if name not in columns:
            op.add_column("api_client", column)
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("api_client")}
    if "uq_api_client_refresh_token_hash" not in indexes:
        op.create_index("uq_api_client_refresh_token_hash", "api_client", ["refresh_token_hash"], unique=True)


def downgrade():
    bind = op.get_bind()
    # SQLite's table-level autoindex for the model-declared unique column
    # prevents safe DROP COLUMN without rebuilding the entire table. SQLite
    # is test-only; retain the additive columns while still moving the
    # Alembic revision backwards. PostgreSQL, the supported production
    # database, performs the complete reversible downgrade below.
    if bind.dialect.name == "sqlite":
        return
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("api_client")}
    if "uq_api_client_refresh_token_hash" in indexes:
        op.drop_index("uq_api_client_refresh_token_hash", table_name="api_client")
    columns = {column["name"] for column in sa.inspect(bind).get_columns("api_client")}
    for column in ("device_model", "platform", "app_build", "app_version", "refresh_expires_at", "access_expires_at", "refresh_token_hash", "client_kind"):
        if column in columns:
            op.drop_column("api_client", column)
