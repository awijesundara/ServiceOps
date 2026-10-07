"""Suppliers and contracts, with contracts linked to configuration items.

Revision ID: 20261007_0115
Revises: 20261007_0114
"""
from alembic import op
import sqlalchemy as sa

revision = "20261007_0115"
down_revision = "20261007_0114"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "supplier" not in tables:
        op.create_table(
            "supplier",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("supplier_type", sa.String(40), nullable=False, server_default="Vendor"),
            sa.Column("website", sa.String(255), nullable=False, server_default=""),
            sa.Column("email", sa.String(255), nullable=False, server_default=""),
            sa.Column("phone", sa.String(60), nullable=False, server_default=""),
            sa.Column("address", sa.Text(), nullable=False, server_default=""),
            sa.Column("account_number", sa.String(80), nullable=False, server_default=""),
            sa.Column("notes", sa.Text(), nullable=False, server_default=""),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("tenant_id", "name", name="uq_supplier_tenant_name"),
        )
    if "contract" not in tables:
        op.create_table(
            "contract",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("number", sa.String(80), nullable=False, server_default=""),
            sa.Column("contract_type", sa.String(40), nullable=False, server_default="Support"),
            sa.Column("supplier_id", sa.Integer(), sa.ForeignKey("supplier.id"), index=True),
            sa.Column("start_date", sa.Date()),
            sa.Column("end_date", sa.Date(), index=True),
            sa.Column("notice_days", sa.Integer(), nullable=False, server_default="30"),
            sa.Column("renewal", sa.String(20), nullable=False, server_default="none"),
            sa.Column("cost", sa.Numeric(14, 2)),
            sa.Column("currency", sa.String(3), nullable=False, server_default="JPY"),
            sa.Column("billing_period", sa.String(20), nullable=False, server_default="yearly"),
            sa.Column("owner_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.Column("notes", sa.Text(), nullable=False, server_default=""),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("alerted_for_end_date", sa.Date()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
    if "contract_ci" not in tables:
        op.create_table(
            "contract_ci",
            sa.Column("contract_id", sa.Integer(), sa.ForeignKey("contract.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("ci_id", sa.Integer(), sa.ForeignKey("configuration_item.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
        )


def downgrade():
    op.drop_table("contract_ci")
    op.drop_table("contract")
    op.drop_table("supplier")
