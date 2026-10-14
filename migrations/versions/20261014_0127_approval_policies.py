"""Configurable approval policies (B-460): approval_policy and
approval_policy_stage, and catalog_item.approval_policy_id.

Additive. Default policies are created by the application per tenant the
first time they are needed (serviceops_core.approval_policies). The
downgrade drops the column and tables.

Revision ID: 20261014_0127
Revises: 20261014_0126
"""
from alembic import op
import sqlalchemy as sa

revision = "20261014_0127"
down_revision = "20261014_0126"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    bind = op.get_bind()
    if "approval_policy" in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        "approval_policy",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("applies_to", sa.String(20), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("updated_by_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "applies_to", "name", name="uq_approval_policy_name"),
    )
    op.create_table(
        "approval_policy_stage",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
        sa.Column("policy_id", sa.Integer(), sa.ForeignKey("approval_policy.id", ondelete="CASCADE"), nullable=False,
                  index=True),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("source", sa.String(40), nullable=False),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("support_group.id")),
        sa.Column("role_filter", sa.String(60)),
        sa.Column("include_manager", sa.Boolean(), nullable=False),
        sa.Column("authority", sa.String(20)),
        sa.Column("user_ids_json", sa.Text(), nullable=False),
        sa.Column("mode", sa.String(12), nullable=False),
        sa.Column("condition", sa.String(40), nullable=False),
        sa.Column("fallback", sa.String(30), nullable=False),
        sa.Column("skip_duplicates", sa.Boolean(), nullable=False),
    )
    with op.batch_alter_table("catalog_item") as batch:
        batch.add_column(sa.Column("approval_policy_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("catalog_item_approval_policy_id_fkey", "approval_policy", ["approval_policy_id"],
                                 ["id"], ondelete="SET NULL")


def downgrade():
    bind = op.get_bind()
    present = {column["name"] for column in sa.inspect(bind).get_columns("catalog_item")}
    if "approval_policy_id" in present:
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table("catalog_item", recreate="always") as batch:
                batch.drop_column("approval_policy_id")
        else:
            for fk in sa.inspect(bind).get_foreign_keys("catalog_item"):
                if fk["name"] and fk["constrained_columns"] == ["approval_policy_id"]:
                    op.drop_constraint(fk["name"], "catalog_item", type_="foreignkey")
            op.drop_column("catalog_item", "approval_policy_id")
    op.drop_table("approval_policy_stage")
    op.drop_table("approval_policy")
