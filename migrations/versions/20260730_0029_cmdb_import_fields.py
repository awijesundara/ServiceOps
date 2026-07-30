"""Add external_source, external_id to configuration_item, backing bulk CMDB
import from external inventory systems (serviceops_core/netbox_sync.py,
serviceops_core/cmdb_import.py). These let a re-run of a NetBox sync or CSV
import match existing rows instead of creating duplicates. Both columns are
nullable: manually-created CIs (the vast majority today) have neither.

Revision ID: 20260730_0029
Revises: 20260730_0028
"""
from alembic import op
import sqlalchemy as sa

revision = "20260730_0029"
down_revision = "20260730_0028"
branch_labels = None
depends_on = None

INDEX_NAME = "uq_ci_tenant_external_source_id"


def upgrade():
    bind = op.get_bind()
    columns = {col["name"] for col in sa.inspect(bind).get_columns("configuration_item")}
    with op.batch_alter_table("configuration_item") as batch:
        if "external_source" not in columns:
            batch.add_column(sa.Column("external_source", sa.String(length=20), nullable=True))
        if "external_id" not in columns:
            batch.add_column(sa.Column("external_id", sa.String(length=120), nullable=True))

    indexes = {idx["name"] for idx in sa.inspect(bind).get_indexes("configuration_item")}
    if INDEX_NAME not in indexes:
        op.create_index(
            INDEX_NAME,
            "configuration_item",
            ["tenant_id", "external_source", "external_id"],
            unique=True,
            sqlite_where=sa.text("external_id IS NOT NULL"),
            postgresql_where=sa.text("external_id IS NOT NULL"),
        )


def downgrade():
    bind = op.get_bind()
    indexes = {idx["name"] for idx in sa.inspect(bind).get_indexes("configuration_item")}
    if INDEX_NAME in indexes:
        op.drop_index(INDEX_NAME, table_name="configuration_item")
    with op.batch_alter_table("configuration_item") as batch:
        batch.drop_column("external_id")
        batch.drop_column("external_source")
