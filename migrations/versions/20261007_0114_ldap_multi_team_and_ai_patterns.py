"""Let one AD/LDAP group map to several ServiceOps groups, and add the
administrator's sensitive / not-sensitive AI patterns.

Revision ID: 20261007_0114
Revises: 20261006_0113
"""
from alembic import op
import sqlalchemy as sa

revision = "20261007_0114"
down_revision = "20261006_0113"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def _unique_names(table):
    return {c["name"] for c in sa.inspect(op.get_bind()).get_unique_constraints(table) if c.get("name")}


def upgrade():
    names = _unique_names("directory_group_mapping")
    with op.batch_alter_table("directory_group_mapping") as batch:
        if "uq_directory_group_mapping_tenant_group" in names:
            batch.drop_constraint("uq_directory_group_mapping_tenant_group", type_="unique")
        if "uq_directory_group_mapping_tenant_group_team" not in names:
            batch.create_unique_constraint(
                "uq_directory_group_mapping_tenant_group_team", ["tenant_id", "directory_group", "support_group_id"]
            )
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("ai_configuration")}
    for name in ("sensitive_patterns", "safe_patterns"):
        if name not in columns:
            op.add_column("ai_configuration", sa.Column(name, sa.Text(), nullable=False, server_default=""))


def downgrade():
    with op.batch_alter_table("ai_configuration") as batch:
        batch.drop_column("safe_patterns")
        batch.drop_column("sensitive_patterns")
    # One team per AD group again: keep the earliest mapping of each group.
    op.execute(sa.text(
        "DELETE FROM directory_group_mapping WHERE id NOT IN ("
        "SELECT MIN(id) FROM directory_group_mapping GROUP BY tenant_id, directory_group)"
    ))
    with op.batch_alter_table("directory_group_mapping") as batch:
        batch.drop_constraint("uq_directory_group_mapping_tenant_group_team", type_="unique")
        batch.create_unique_constraint("uq_directory_group_mapping_tenant_group", ["tenant_id", "directory_group"])
