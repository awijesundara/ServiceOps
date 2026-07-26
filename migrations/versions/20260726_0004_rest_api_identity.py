"""Add tenant-scoped REST API clients and idempotency records.

Revision ID: 20260726_0004
Revises: 20260726_0003
"""
from alembic import op
import sqlalchemy as sa

revision = "20260726_0004"
down_revision = "20260726_0003"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "api_client" not in tables:
        op.create_table(
            "api_client",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("client_id", sa.String(length=36), nullable=False),
            sa.Column("name", sa.String(length=160), nullable=False),
            sa.Column("token_prefix", sa.String(length=16), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("scopes_json", sa.Text(), nullable=False),
            sa.Column("acting_user_id", sa.Integer(), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False),
            sa.Column("created_by_id", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("tenant_id", sa.Integer(), nullable=False),
            sa.ForeignKeyConstraint(["acting_user_id"], ["user.id"]),
            sa.ForeignKeyConstraint(["created_by_id"], ["user.id"]),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"]),
            sa.UniqueConstraint("client_id", name="uq_api_client_client_id"),
            sa.UniqueConstraint("token_hash", name="uq_api_client_token_hash"),
        )
        op.create_index("ix_api_client_tenant_id", "api_client", ["tenant_id"])
    tables = set(sa.inspect(bind).get_table_names())
    if "api_idempotency_record" not in tables:
        op.create_table(
            "api_idempotency_record",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("api_client_id", sa.Integer(), nullable=False),
            sa.Column("idempotency_key", sa.String(length=128), nullable=False),
            sa.Column("method", sa.String(length=10), nullable=False),
            sa.Column("path", sa.String(length=255), nullable=False),
            sa.Column("request_hash", sa.String(length=64), nullable=False),
            sa.Column("response_status", sa.Integer(), nullable=False),
            sa.Column("response_body", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.Integer(), nullable=False),
            sa.ForeignKeyConstraint(["api_client_id"], ["api_client.id"]),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"]),
            sa.UniqueConstraint(
                "api_client_id", "idempotency_key",
                name="uq_api_idempotency_client_key",
            ),
        )
        op.create_index(
            "ix_api_idempotency_record_tenant_id",
            "api_idempotency_record", ["tenant_id"],
        )


def downgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "api_idempotency_record" in tables:
        op.drop_table("api_idempotency_record")
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "api_client" in tables:
        op.drop_table("api_client")
