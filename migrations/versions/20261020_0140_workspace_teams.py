"""Workspace teams: which team handles each enterprise workspace (HR, security, ...).

Records in a workspace were never given an owning team, so HR, security,
risk and customer records were visible only to whoever raised them.

Revision ID: 20261020_0140
Revises: 20261020_0139
"""
from alembic import op
import sqlalchemy as sa

revision = "20261020_0140"
down_revision = "20261020_0139"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    if "workspace_team" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "workspace_team",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
        sa.Column("domain", sa.String(40), nullable=False),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("support_group.id"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "domain", name="uq_workspace_team_tenant_domain"),
    )


def downgrade():
    op.drop_table("workspace_team")
