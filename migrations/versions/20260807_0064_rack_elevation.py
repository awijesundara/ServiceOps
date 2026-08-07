"""Add rack table and physical rack-placement columns on configuration_item.

Revision ID: 20260807_0064
Revises: 20260806_0063
"""
from alembic import op
import sqlalchemy as sa

revision = "20260807_0064"
down_revision = "20260806_0063"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    # 20260726_0001 (the baseline migration) creates every table/column
    # present in the current ORM metadata on a fresh database, so both the
    # new table and the new configuration_item columns already exist by the
    # time this migration runs there; on a DB that predates this change,
    # they don't. Guard both the same way every other post-baseline
    # migration that adds a table or column already does (e.g. 20260806_0061,
    # 20260806_0063).
    if not inspector.has_table("rack"):
        op.create_table(
            "rack",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("name", sa.String(120), nullable=False),
            sa.Column("site", sa.String(120), nullable=False, server_default=""),
            sa.Column("u_height", sa.Integer(), nullable=False, server_default="42"),
            sa.Column("notes", sa.Text(), nullable=False, server_default=""),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("external_source", sa.String(20)),
            sa.Column("external_id", sa.String(120)),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "name", name="uq_rack_tenant_name"),
        )
        op.create_index("ix_rack_tenant_id", "rack", ["tenant_id"])

    ci_columns = [c["name"] for c in inspector.get_columns("configuration_item")]
    with op.batch_alter_table("configuration_item") as batch:
        if "rack_id" not in ci_columns:
            batch.add_column(sa.Column("rack_id", sa.Integer()))
        if "rack_position" not in ci_columns:
            batch.add_column(sa.Column("rack_position", sa.Float()))
        if "rack_u_height" not in ci_columns:
            batch.add_column(sa.Column("rack_u_height", sa.Integer()))
        if "rack_face" not in ci_columns:
            batch.add_column(sa.Column("rack_face", sa.String(10)))

    # FK constraint + index as their own pass, and only on real (Postgres)
    # deployments. Reproduced repeatedly -- a fresh install AND a downgrade/
    # re-upgrade cycle -- that SQLite's batch-mode table-recreate loses
    # track of rack_id when a create_foreign_key/create_index follows its
    # add_column, even in a separate later batch block; SQLite is test-
    # harness-only here (PostgreSQL is this app's only supported production
    # database), so the constraint/index are skipped there rather than
    # fighting an alembic/SQLite batch-mode limitation neither this
    # migration nor production correctness depends on.
    if "rack_id" not in ci_columns and bind.dialect.name != "sqlite":
        with op.batch_alter_table("configuration_item") as batch:
            batch.create_foreign_key("fk_configuration_item_rack_id", "rack", ["rack_id"], ["id"])
            batch.create_index("ix_configuration_item_rack_id", ["rack_id"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    rack_fks = [
        fk["name"] for fk in inspector.get_foreign_keys("configuration_item")
        if fk.get("referred_table") == "rack" and fk["name"]
    ]
    # On a fresh install (baseline metadata.create_all, index=True on the
    # ORM column) or a real Postgres deployment, rack_id already has this
    # index -- batch mode's table-recreate reflects it and tries to carry
    # it forward onto the recreated (rack_id-less) table unless it's
    # dropped explicitly first, which fails the same way an un-dropped FK
    # constraint would.
    rack_indexes = [
        ix["name"] for ix in inspector.get_indexes("configuration_item")
        if ix["name"] and list(ix.get("column_names", ())) == ["rack_id"]
    ]
    with op.batch_alter_table("configuration_item") as batch:
        for ix_name in rack_indexes:
            batch.drop_index(ix_name)
        for fk_name in rack_fks:
            batch.drop_constraint(fk_name, type_="foreignkey")
        batch.drop_column("rack_face")
        batch.drop_column("rack_u_height")
        batch.drop_column("rack_position")
        batch.drop_column("rack_id")
    op.drop_table("rack")
