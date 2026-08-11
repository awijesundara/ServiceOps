"""Client Management phase 5: per-organization SLA policy overrides --
SLADefinition.client_organization_id (nullable; null = tenant-wide default,
matching this app's existing "no override row = default" convention).

Revision ID: 20260811_0071
Revises: 20260811_0070
"""
from alembic import op
import sqlalchemy as sa

revision = "20260811_0071"
down_revision = "20260811_0070"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("sla_definition")]
    if "client_organization_id" not in columns:
        with op.batch_alter_table("sla_definition") as batch:
            batch.add_column(sa.Column("client_organization_id", sa.Integer()))
        if bind.dialect.name != "sqlite":
            with op.batch_alter_table("sla_definition") as batch:
                batch.create_foreign_key(
                    "fk_sla_definition_client_organization_id",
                    "client_organization", ["client_organization_id"], ["id"],
                )
                batch.create_index(
                    "ix_sla_definition_client_organization_id", ["client_organization_id"],
                )


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("sla_definition")]
    if "client_organization_id" in columns:
        fks = [
            fk["name"] for fk in inspector.get_foreign_keys("sla_definition")
            if fk.get("referred_table") == "client_organization" and fk["name"]
        ]
        indexes = [
            ix["name"] for ix in inspector.get_indexes("sla_definition")
            if ix["name"] and list(ix.get("column_names", ())) == ["client_organization_id"]
        ]
        with op.batch_alter_table("sla_definition") as batch:
            for ix_name in indexes:
                batch.drop_index(ix_name)
            for fk_name in fks:
                batch.drop_constraint(fk_name, type_="foreignkey")
            batch.drop_column("client_organization_id")
