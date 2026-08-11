"""B-121 configurable workspace: UserWorkspaceLayout stores each user's
personal "My Workspace" widget selection/order, picked from a fixed,
code-defined catalog (no free-text/arbitrary widget content).

Revision ID: 20260811_0077
Revises: 20260811_0076
"""
from alembic import op
import sqlalchemy as sa

revision = "20260811_0077"
down_revision = "20260811_0076"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("user_workspace_layout"):
        op.create_table(
            "user_workspace_layout",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False, unique=True),
            sa.Column("layout_json", sa.JSON(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_user_workspace_layout_tenant_id", "user_workspace_layout", ["tenant_id"])


def downgrade():
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("user_workspace_layout"):
        op.drop_table("user_workspace_layout")
