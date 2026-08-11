"""Client Management phase 3: ClientView (saved filters/sort for the
customer ticket list).

Revision ID: 20260811_0069
Revises: 20260810_0068
"""
from alembic import op
import sqlalchemy as sa

revision = "20260811_0069"
down_revision = "20260810_0068"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("client_view"):
        op.create_table(
            "client_view",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("name", sa.String(120), nullable=False),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("shared", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("conditions_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("sort_field", sa.String(30), nullable=False, server_default="updated"),
            sa.Column("sort_dir", sa.String(4), nullable=False, server_default="desc"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint(
                "tenant_id", "created_by_id", "name", name="uq_client_view_tenant_owner_name",
            ),
        )
        op.create_index("ix_client_view_tenant_id", "client_view", ["tenant_id"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("client_view"):
        op.drop_table("client_view")
