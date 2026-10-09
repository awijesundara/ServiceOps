"""Groups as approvers: link a support group to an approval authority (CCB,
executive, a team's manager assessment, enterprise record approval) so every
active member of that group is an approver alongside the named users.

Revision ID: 20261009_0117
Revises: 20261008_0116
"""
from alembic import op
import sqlalchemy as sa

revision = "20261009_0117"
down_revision = "20261008_0116"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    if "approval_authority_group" in set(sa.inspect(op.get_bind()).get_table_names()):
        return
    op.create_table(
        "approval_authority_group",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
        sa.Column("authority", sa.String(40), nullable=False),
        # The team whose manager assessment this group may also approve;
        # null for tenant-wide authorities (CCB, executive, enterprise).
        sa.Column("subject_group_id", sa.Integer(), sa.ForeignKey("support_group.id", ondelete="CASCADE"), index=True),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("support_group.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "authority", "subject_group_id", "group_id",
                            name="uq_approval_authority_group"),
    )


def downgrade():
    op.drop_table("approval_authority_group")
