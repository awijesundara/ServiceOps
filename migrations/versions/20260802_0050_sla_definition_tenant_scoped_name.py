"""sla_definition.name was uniquely constrained tenant-wide, so a second
tenant could never create its own "Standard Incident SLA"/etc -- the same
class of bug already fixed for support_group.name in 20260731_0049.
Rescopes uniqueness to (tenant_id, name).

Revision ID: 20260802_0050
Revises: 20260731_0049
"""
from alembic import op
import sqlalchemy as sa

revision = "20260802_0050"
down_revision = "20260731_0049"
branch_labels = None
depends_on = None

TABLE = "sla_definition"
COMPOSITE_NAME = "uq_sla_definition_tenant_name"


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_composite = any(
        uc["name"] == COMPOSITE_NAME for uc in inspector.get_unique_constraints(TABLE)
    )
    if existing_composite:
        return

    name_only_constraints = [
        uc["name"] for uc in inspector.get_unique_constraints(TABLE)
        if uc["column_names"] == ["name"] and uc["name"]
    ]
    name_only_indexes = [
        idx["name"] for idx in inspector.get_indexes(TABLE)
        if idx.get("unique") and idx["column_names"] == ["name"] and idx["name"]
        and idx["name"] not in name_only_constraints
    ]

    with op.batch_alter_table(TABLE) as batch_op:
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
    with op.batch_alter_table(TABLE) as batch_op:
        batch_op.drop_constraint(COMPOSITE_NAME, type_="unique")
        batch_op.create_unique_constraint("uq_sla_definition_name", ["name"])
