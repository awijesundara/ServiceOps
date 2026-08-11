"""Client Management phase 4: ClientMacro (one-click bulk actions/canned
replies for customer tickets).

Revision ID: 20260811_0070
Revises: 20260811_0069
"""
from alembic import op
import sqlalchemy as sa

revision = "20260811_0070"
down_revision = "20260811_0069"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("client_macro"):
        op.create_table(
            "client_macro",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("name", sa.String(120), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("actions_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("reply_body", sa.Text(), nullable=False, server_default=""),
            sa.Column("reply_visibility", sa.String(20), nullable=False, server_default="public"),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "name", name="uq_client_macro_tenant_name"),
        )
        op.create_index("ix_client_macro_tenant_id", "client_macro", ["tenant_id"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("client_macro"):
        op.drop_table("client_macro")
