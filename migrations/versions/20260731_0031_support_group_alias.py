"""Add support_group_alias table so alternate team names (e.g. "DBA" for
"Database") resolve to the same SupportGroup wherever a team is looked up
from free text (CSV import's Owner column, etc.) instead of a dropdown.

Revision ID: 20260731_0031
Revises: 20260731_0030
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0031"
down_revision = "20260731_0030"
branch_labels = None
depends_on = None

TABLE_NAME = "support_group_alias"


def upgrade():
    bind = op.get_bind()
    if TABLE_NAME not in sa.inspect(bind).get_table_names():
        op.create_table(
            TABLE_NAME,
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("alias", sa.String(length=160), nullable=False),
            sa.Column("group_id", sa.Integer(), sa.ForeignKey("support_group.id"), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "alias", name="uq_support_group_alias_tenant_alias"),
        )
        op.create_index(
            "ix_support_group_alias_tenant_id", TABLE_NAME, ["tenant_id"],
        )


def downgrade():
    bind = op.get_bind()
    if TABLE_NAME in sa.inspect(bind).get_table_names():
        op.drop_index("ix_support_group_alias_tenant_id", table_name=TABLE_NAME)
        op.drop_table(TABLE_NAME)
