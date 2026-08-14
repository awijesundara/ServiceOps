"""Add tenant-scoped WebAuthn credentials and single-use challenges.

Revision ID: 20260814_0081
Revises: 20260814_0080
"""
from alembic import op
import sqlalchemy as sa


revision = "20260814_0081"
down_revision = "20260814_0080"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "passkey_credential" not in tables:
        op.create_table(
            "passkey_credential",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("credential_id", sa.LargeBinary(), nullable=False, unique=True),
            sa.Column("public_key", sa.LargeBinary(), nullable=False),
            sa.Column("sign_count", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("name", sa.String(120), nullable=False, server_default="Passkey"),
            sa.Column("transports_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_used_at", sa.DateTime(timezone=True)),
        )
        op.create_index("ix_passkey_credential_user_id", "passkey_credential", ["user_id"])
        op.create_index("ix_passkey_credential_tenant_id", "passkey_credential", ["tenant_id"])
        op.create_index("ix_passkey_credential_tenant_user", "passkey_credential", ["tenant_id", "user_id"])
    if "passkey_challenge" not in tables:
        op.create_table(
            "passkey_challenge",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("challenge", sa.LargeBinary(), nullable=False),
            sa.Column("purpose", sa.String(20), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id")),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_passkey_challenge_user_id", "passkey_challenge", ["user_id"])
        op.create_index("ix_passkey_challenge_tenant_id", "passkey_challenge", ["tenant_id"])
        op.create_index("ix_passkey_challenge_expires_at", "passkey_challenge", ["expires_at"])


def downgrade():
    # Deliberately retain both additive tables when rolling the application
    # back. Dropping passkey_credential would irreversibly delete every user's
    # public-key registration and force re-enrollment. Revision 0080 simply
    # ignores these tables; rolling forward reuses them idempotently.
    pass
