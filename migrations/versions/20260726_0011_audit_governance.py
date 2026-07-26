"""Add versioned audit keys and retention governance.

Revision ID: 20260726_0011
Revises: 20260726_0010
"""
from alembic import op
import sqlalchemy as sa

revision = "20260726_0011"
down_revision = "20260726_0010"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    audit_columns = {column["name"] for column in inspector.get_columns("audit")}
    if "integrity_key_id" not in audit_columns:
        with op.batch_alter_table("audit") as batch:
            batch.add_column(sa.Column(
                "integrity_key_id", sa.String(80), nullable=False,
                server_default="environment-v1",
            ))
    tables = set(sa.inspect(bind).get_table_names())
    if "audit_integrity_key" not in tables:
        op.create_table(
            "audit_integrity_key",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("key_id", sa.String(80), nullable=False),
            sa.Column("secret_encrypted", sa.Text(), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("retired_at", sa.DateTime(timezone=True)),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.UniqueConstraint(
                "tenant_id", "key_id", name="uq_audit_key_tenant_key"
            ),
        )
        op.create_index(
            "ix_audit_integrity_key_tenant_id",
            "audit_integrity_key", ["tenant_id"],
        )
    if "audit_retention_policy" not in tables:
        op.create_table(
            "audit_retention_policy",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("retention_days", sa.Integer(), nullable=False),
            sa.Column("legal_hold", sa.Boolean(), nullable=False),
            sa.Column("external_export_required", sa.Boolean(), nullable=False),
            sa.Column("updated_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.UniqueConstraint("tenant_id", name="uq_audit_retention_tenant"),
        )
        op.create_index(
            "ix_audit_retention_policy_tenant_id",
            "audit_retention_policy", ["tenant_id"], unique=True,
        )


def downgrade():
    # These additions are intentionally retained for old-application compatibility.
    # Dropping historical verification keys or their event identifiers would make
    # an application rollback destroy security evidence.
    pass
