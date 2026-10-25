"""service_offering.name was uniquely constrained installation-wide, so a
second tenant could never create its own "Email"/"Payments" service -- the
same class of bug already fixed for support_group (20260731_0049) and
sla_definition (20260802_0050). Rescopes uniqueness to (tenant_id, name) now
that administrators can create services from the Service offerings page.

Revision ID: 20261023_0142
Revises: 20261021_0141
"""
from alembic import op
import sqlalchemy as sa

revision = "20261023_0142"
down_revision = "20261021_0141"
branch_labels = None
depends_on = None
serviceops_migration_phase = "contract"
serviceops_contract_after_version = "1.113.67"

TABLE = "service_offering"
COMPOSITE_NAME = "uq_service_offering_tenant_name"


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_composite = any(
        uc["name"] == COMPOSITE_NAME for uc in inspector.get_unique_constraints(TABLE)
    )
    if existing_composite:
        return

    name_only_constraints = [
        uc["name"] or "uq_service_offering_name" for uc in inspector.get_unique_constraints(TABLE)
        if uc["column_names"] == ["name"]
    ]
    name_only_indexes = [
        idx["name"] for idx in inspector.get_indexes(TABLE)
        if idx.get("unique") and idx["column_names"] == ["name"] and idx["name"]
        and idx["name"] not in name_only_constraints
    ]

    with op.batch_alter_table(TABLE, naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"}) as batch_op:
        for constraint_name in name_only_constraints:
            batch_op.drop_constraint(constraint_name, type_="unique")
        for index_name in name_only_indexes:
            batch_op.drop_index(index_name)
        batch_op.create_unique_constraint(COMPOSITE_NAME, ["tenant_id", "name"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_composite = any(
        uc["name"] == COMPOSITE_NAME for uc in inspector.get_unique_constraints(TABLE)
    )
    if not existing_composite:
        return
    duplicates = bind.execute(sa.text(
        "SELECT 1 FROM service_offering GROUP BY name HAVING COUNT(*) > 1 LIMIT 1"
    )).first()
    if duplicates:
        raise RuntimeError("Cannot restore global service-name uniqueness while tenants share names")
    with op.batch_alter_table(TABLE, naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"}) as batch_op:
        batch_op.drop_constraint(COMPOSITE_NAME, type_="unique")
        batch_op.create_unique_constraint("uq_service_offering_name", ["name"])
