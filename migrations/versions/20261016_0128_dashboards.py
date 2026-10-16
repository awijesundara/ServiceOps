"""Customizable dashboards (B-464): dashboard, dashboard_widget and
dashboard_home.

Additive. Personal dashboards are created by the application the first
time a person opens Dashboards, from their My Workspace layout when they
have one; user_workspace_layout is left in place. The downgrade drops the
three tables.

Revision ID: 20261016_0128
Revises: 20261014_0127
"""
from alembic import op
import sqlalchemy as sa

revision = "20261016_0128"
down_revision = "20261014_0127"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    bind = op.get_bind()
    if "dashboard" in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        "dashboard",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
        sa.Column("scope", sa.String(10), nullable=False),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("user.id", ondelete="CASCADE"), index=True),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("support_group.id", ondelete="CASCADE"), index=True),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("description", sa.String(255), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "dashboard_widget",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
        sa.Column("dashboard_id", sa.Integer(), sa.ForeignKey("dashboard.id", ondelete="CASCADE"), nullable=False,
                  index=True),
        sa.Column("widget_key", sa.String(60), nullable=False),
        sa.Column("title", sa.String(120)),
        sa.Column("span", sa.Integer(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("options_json", sa.Text(), nullable=False),
    )
    op.create_table(
        "dashboard_home",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
        sa.Column("dashboard_id", sa.Integer(), sa.ForeignKey("dashboard.id", ondelete="CASCADE"), nullable=False),
    )


def downgrade():
    op.drop_table("dashboard_home")
    op.drop_table("dashboard_widget")
    op.drop_table("dashboard")
