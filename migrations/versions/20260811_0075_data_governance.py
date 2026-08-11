"""B-090 data governance: DataRetentionPolicy (per-tenant/record-type
retention window), RecordLegalHold (per-record purge exemption),
ClientContact.erased_at (GDPR Art. 17 erasure, mirroring User.erased_at).

Revision ID: 20260811_0075
Revises: 20260811_0074
"""
from alembic import op
import sqlalchemy as sa

revision = "20260811_0075"
down_revision = "20260811_0074"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("data_retention_policy"):
        op.create_table(
            "data_retention_policy",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("record_type", sa.String(40), nullable=False),
            sa.Column("retention_days", sa.Integer(), nullable=False, server_default="730"),
            sa.Column("legal_hold", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("last_run_at", sa.DateTime(timezone=True)),
            sa.Column("last_run_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("updated_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "record_type", name="uq_data_retention_policy_tenant_record_type"),
        )
        op.create_index("ix_data_retention_policy_tenant_id", "data_retention_policy", ["tenant_id"])

    if not inspector.has_table("record_legal_hold"):
        op.create_table(
            "record_legal_hold",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("record_type", sa.String(40), nullable=False),
            sa.Column("record_id", sa.Integer(), nullable=False),
            sa.Column("reason", sa.String(500), nullable=False),
            sa.Column("applied_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("applied_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("released_at", sa.DateTime(timezone=True)),
            sa.Column("released_by_id", sa.Integer(), sa.ForeignKey("user.id")),
        )
        op.create_index(
            "ix_record_legal_hold_lookup", "record_legal_hold",
            ["tenant_id", "record_type", "record_id"],
        )

    contact_columns = [c["name"] for c in inspector.get_columns("client_contact")]
    if "erased_at" not in contact_columns:
        with op.batch_alter_table("client_contact") as batch:
            batch.add_column(sa.Column("erased_at", sa.DateTime(timezone=True)))


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    contact_columns = [c["name"] for c in inspector.get_columns("client_contact")]
    if "erased_at" in contact_columns:
        with op.batch_alter_table("client_contact") as batch:
            batch.drop_column("erased_at")

    if inspector.has_table("record_legal_hold"):
        op.drop_table("record_legal_hold")

    if inspector.has_table("data_retention_policy"):
        op.drop_table("data_retention_policy")
