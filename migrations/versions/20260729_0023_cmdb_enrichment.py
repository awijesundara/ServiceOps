"""Enrich CMDB: CI attributes, lifecycle, ownership, discovery, and tenant-scoped relationships.

Revision ID: 20260729_0023
Revises: 20260729_0022
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_0023"
down_revision = "20260729_0022"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    ci_columns = {col["name"] for col in inspector.get_columns("configuration_item")}

    def add_ci_column(name, column):
        if name not in ci_columns:
            op.add_column("configuration_item", column)

    add_ci_column("description", sa.Column("description", sa.Text(), nullable=True))
    add_ci_column("lifecycle_state", sa.Column(
        "lifecycle_state", sa.String(length=30), nullable=False, server_default="In Use",
    ))
    add_ci_column("business_criticality", sa.Column(
        "business_criticality", sa.String(length=20), nullable=False, server_default="Medium",
    ))
    add_ci_column("serial_number", sa.Column("serial_number", sa.String(length=120), nullable=True))
    add_ci_column("vendor", sa.Column("vendor", sa.String(length=120), nullable=True))
    add_ci_column("model", sa.Column("model", sa.String(length=120), nullable=True))
    add_ci_column("location", sa.Column("location", sa.String(length=160), nullable=True))
    add_ci_column("cost_center", sa.Column("cost_center", sa.String(length=80), nullable=True))
    add_ci_column("discovery_source", sa.Column(
        "discovery_source", sa.String(length=40), nullable=False, server_default="Manual",
    ))
    add_ci_column("install_date", sa.Column("install_date", sa.Date(), nullable=True))
    add_ci_column("warranty_expiry_date", sa.Column("warranty_expiry_date", sa.Date(), nullable=True))
    add_ci_column("attributes", sa.Column(
        "attributes", sa.JSON(), nullable=False, server_default=sa.text("'{}'"),
    ))
    add_ci_column("support_group_id", sa.Column(
        "support_group_id", sa.Integer(), sa.ForeignKey("support_group.id"), nullable=True,
    ))
    add_ci_column("created_at", sa.Column(
        "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(),
    ))
    add_ci_column("updated_at", sa.Column(
        "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(),
    ))

    rel_columns = {col["name"] for col in inspector.get_columns("ci_relationship")}
    if "tenant_id" not in rel_columns:
        op.add_column("ci_relationship", sa.Column("tenant_id", sa.Integer(), nullable=True))
        op.execute(
            "UPDATE ci_relationship SET tenant_id = ("
            "SELECT configuration_item.tenant_id FROM configuration_item "
            "WHERE configuration_item.id = ci_relationship.parent_id)"
        )
        op.alter_column("ci_relationship", "tenant_id", nullable=False)
        op.create_foreign_key(
            "fk_ci_relationship_tenant", "ci_relationship", "tenant", ["tenant_id"], ["id"],
        )
        op.create_index("ix_ci_relationship_tenant_id", "ci_relationship", ["tenant_id"])
    if "created_at" not in rel_columns:
        op.add_column("ci_relationship", sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(),
        ))

    existing_constraints = {uc["name"] for uc in inspector.get_unique_constraints("ci_relationship")}
    if "uq_ci_relationship" not in existing_constraints:
        # Drop any pre-existing (parent_id, child_id) duplicate pairs with differing
        # relationship_type before enforcing the tighter three-column constraint.
        op.create_unique_constraint(
            "uq_ci_relationship", "ci_relationship", ["parent_id", "child_id", "relationship_type"],
        )


def downgrade():
    op.drop_constraint("uq_ci_relationship", "ci_relationship", type_="unique")
    op.drop_column("ci_relationship", "created_at")
    op.drop_index("ix_ci_relationship_tenant_id", table_name="ci_relationship")
    op.drop_constraint("fk_ci_relationship_tenant", "ci_relationship", type_="foreignkey")
    op.drop_column("ci_relationship", "tenant_id")

    for column in [
        "updated_at", "created_at", "support_group_id", "attributes", "warranty_expiry_date",
        "install_date", "discovery_source", "cost_center", "location", "model", "vendor",
        "serial_number", "business_criticality", "lifecycle_state", "description",
    ]:
        op.drop_column("configuration_item", column)
