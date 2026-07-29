"""Widen change_governance.conflict_status so multi-ticket conflict messages don't overflow.

Revision ID: 20260729_0018
Revises: 20260729_0017
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_0018"
down_revision = "20260729_0017"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("change_governance") as batch:
        batch.alter_column(
            "conflict_status",
            existing_type=sa.String(40),
            type_=sa.String(500),
            existing_nullable=False,
        )


def downgrade():
    op.execute("UPDATE change_governance SET conflict_status = substr(conflict_status, 1, 40)")
    with op.batch_alter_table("change_governance") as batch:
        batch.alter_column(
            "conflict_status",
            existing_type=sa.String(500),
            type_=sa.String(40),
            existing_nullable=False,
        )
