"""Create the default tenant and scope tenant-owned root records.

Revision ID: 20260726_0002
Revises: 20260726_0001
"""
from alembic import op
import sqlalchemy as sa

revision = "20260726_0002"
down_revision = "20260726_0001"
branch_labels = None
depends_on = None

TENANT_TABLES = (
    "user",
    "platform_setting",
    "ticket",
    "knowledge",
    "asset",
    "audit",
    "enterprise_record",
    "catalog_item",
    "configuration_item",
    "notification",
    "support_group",
    "approval_chain",
    "service_offering",
    "sla_definition",
    "catalog_request",
)


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "tenant" not in inspector.get_table_names():
        op.create_table(
            "tenant",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("slug", sa.String(length=80), nullable=False, unique=True),
            sa.Column("name", sa.String(length=160), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    exists = bind.execute(
        sa.text("SELECT id FROM tenant WHERE id = 1")
    ).scalar_one_or_none()
    if exists is None:
        bind.execute(sa.text(
            "INSERT INTO tenant (id, slug, name, active, created_at) "
            "VALUES (1, 'default', 'Default organisation', true, CURRENT_TIMESTAMP)"
        ))
    for table_name in TENANT_TABLES:
        columns = {column["name"] for column in sa.inspect(bind).get_columns(table_name)}
        if "tenant_id" in columns:
            continue
        with op.batch_alter_table(table_name) as batch:
            batch.add_column(sa.Column("tenant_id", sa.Integer(), nullable=True))
        bind.execute(sa.text(f'UPDATE "{table_name}" SET tenant_id = 1 WHERE tenant_id IS NULL'))
        with op.batch_alter_table(table_name) as batch:
            batch.alter_column("tenant_id", existing_type=sa.Integer(), nullable=False)
            batch.create_foreign_key(
                f"fk_{table_name}_tenant_id", "tenant", ["tenant_id"], ["id"]
            )
            batch.create_index(f"ix_{table_name}_tenant_id", ["tenant_id"])


def downgrade():
    bind = op.get_bind()
    for table_name in reversed(TENANT_TABLES):
        inspector = sa.inspect(bind)
        columns = {column["name"] for column in inspector.get_columns(table_name)}
        if "tenant_id" not in columns:
            continue
        tenant_indexes = [
            index["name"] for index in inspector.get_indexes(table_name)
            if index["name"] and "tenant_id" in index.get("column_names", ())
        ]
        tenant_foreign_keys = [
            foreign_key["name"] for foreign_key in inspector.get_foreign_keys(table_name)
            if (
                foreign_key["name"]
                and "tenant_id" in foreign_key.get("constrained_columns", ())
            )
        ]
        with op.batch_alter_table(table_name) as batch:
            for index_name in tenant_indexes:
                batch.drop_index(index_name)
            for constraint_name in tenant_foreign_keys:
                batch.drop_constraint(constraint_name, type_="foreignkey")
            batch.drop_column("tenant_id")
    if "tenant" in sa.inspect(bind).get_table_names():
        op.drop_table("tenant")
