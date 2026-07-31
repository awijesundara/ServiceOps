"""support_group.name was uniquely constrained tenant-wide, so a second
tenant could never create its own "Service Desk"/"Change Control Board" --
seed_itil() would hard-fail with an IntegrityError (confirmed by a test
using a second tenant). Rescopes uniqueness to (tenant_id, name).

Revision ID: 20260731_0049
Revises: 20260731_0048
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0049"
down_revision = "20260731_0048"
branch_labels = None
depends_on = None

TABLE = "support_group"
COMPOSITE_NAME = "uq_support_group_tenant_name"


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
    ]

    with op.batch_alter_table(TABLE, recreate="always") as batch_op:
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
    with op.batch_alter_table(TABLE, recreate="always") as batch_op:
        batch_op.drop_constraint(COMPOSITE_NAME, type_="unique")
        batch_op.create_unique_constraint("uq_support_group_name", ["name"])
