"""Asset tags are unique per tenant, not across the installation.

The installation-wide UNIQUE (asset_tag) refused a tag in one tenant because
another tenant used it. It is replaced by a unique index on
(tenant_id, lower(asset_tag)), which keeps the existing case-insensitive rule
inside each tenant. Every earlier application version still works: it checks
tags across all tenants before inserting, which this index allows.

Revision ID: 20261013_0124
Revises: 20261013_0123
"""
from alembic import op
import sqlalchemy as sa

revision = "20261013_0124"
down_revision = "20261013_0123"
branch_labels = None
depends_on = None
serviceops_migration_phase = "contract"
serviceops_contract_after_version = "1.113.40"

INDEX = "uq_asset_tenant_tag"


def _global_unique_constraints(bind):
    return [c["name"] for c in sa.inspect(bind).get_unique_constraints("asset")
            if c["column_names"] == ["asset_tag"]]


def _index_exists(bind):
    # Read the catalogue: SQLAlchemy does not reflect expression indexes on
    # SQLite, and a fresh schema (baseline revision) already has this one.
    if bind.dialect.name == "sqlite":
        sql = "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = :name"
    else:
        sql = "SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = :name"
    return bind.execute(sa.text(sql), {"name": INDEX}).first() is not None


def upgrade():
    bind = op.get_bind()
    if _index_exists(bind):
        return
    if bind.dialect.name == "sqlite":
        # SQLite cannot drop a constraint: rebuild the table without it. A
        # table-level UNIQUE is reflected (unnamed, so name it to drop it); a
        # column-level one is not reflected and disappears in the rebuild.
        unique_indexes = [row for row in bind.exec_driver_sql("PRAGMA index_list(asset)")
                          if row[3] == "u" and [col[2] for col in bind.exec_driver_sql(
                              f"PRAGMA index_info('{row[1]}')")] == ["asset_tag"]]
        if unique_indexes:
            reflected = _global_unique_constraints(bind)
            with op.batch_alter_table("asset", recreate="always",
                                      naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"}) as batch:
                if reflected:
                    batch.drop_constraint(reflected[0] or "uq_asset_asset_tag", type_="unique")
    else:
        for name in _global_unique_constraints(bind):
            op.drop_constraint(name, "asset", type_="unique")
    op.create_index(INDEX, "asset", ["tenant_id", sa.text("lower(asset_tag)")], unique=True)


def downgrade():
    # Fails, as it must, if two tenants now share a tag.
    op.drop_index(INDEX, table_name="asset")
    with op.batch_alter_table("asset") as batch:
        batch.create_unique_constraint("asset_asset_tag_key", ["asset_tag"])
