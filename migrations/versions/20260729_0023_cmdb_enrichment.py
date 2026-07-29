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
    # upgrade() above is unchanged — this migration is already deployed, and
    # only its never-yet-executed downgrade() path is being made to actually
    # work (batch mode: SQLite has no ALTER-based constraint/FK-column-drop
    # support outside the copy-and-move/batch strategy; PostgreSQL behavior
    # is unchanged). Constraint/index names are looked up through the
    # inspector rather than hardcoded, because SQLite doesn't reliably
    # preserve/reflect the name Alembic assigned at creation time (see the
    # identical pattern in 20260726_0002's downgrade).
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tenant_fks = [
        fk["name"] for fk in inspector.get_foreign_keys("ci_relationship")
        if fk["name"] and "tenant_id" in fk.get("constrained_columns", ())
    ]
    tenant_indexes = [
        ix["name"] for ix in inspector.get_indexes("ci_relationship")
        if ix["name"] and "tenant_id" in ix.get("column_names", ())
    ]
    unique_constraints = [
        uc["name"] for uc in inspector.get_unique_constraints("ci_relationship")
        if uc["name"] and set(uc.get("column_names", ())) == {"parent_id", "child_id", "relationship_type"}
    ]
    with op.batch_alter_table("ci_relationship") as batch:
        for uc_name in unique_constraints:
            batch.drop_constraint(uc_name, type_="unique")
        for ix_name in tenant_indexes:
            batch.drop_index(ix_name)
        for fk_name in tenant_fks:
            batch.drop_constraint(fk_name, type_="foreignkey")
        batch.drop_column("created_at")
        batch.drop_column("tenant_id")

    with op.batch_alter_table("configuration_item") as batch:
        for column in [
            "updated_at", "created_at", "support_group_id", "attributes", "warranty_expiry_date",
            "install_date", "discovery_source", "cost_center", "location", "model", "vendor",
            "serial_number", "business_criticality", "lifecycle_state", "description",
        ]:
            batch.drop_column(column)
