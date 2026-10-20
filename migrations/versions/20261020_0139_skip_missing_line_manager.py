"""A requester without a line manager can still request items.

The line-manager step of a catalog approval policy that has a later step is
skipped when the person has no line manager on file (the later steps still
approve). Data only.

Revision ID: 20261020_0139
Revises: 20261020_0138
"""
from alembic import op
import sqlalchemy as sa

revision = "20261020_0139"
down_revision = "20261020_0138"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    bind = op.get_bind()
    rows = bind.execute(sa.text(
        "SELECT s.id, s.policy_id, s.position FROM approval_policy_stage s JOIN approval_policy p ON p.id = s.policy_id "
        "WHERE p.applies_to = 'catalog' AND s.source = 'line_manager' AND s.fallback = 'none'")).fetchall()
    for stage_id, policy_id, position in rows:
        later = bind.execute(sa.text("SELECT COUNT(*) FROM approval_policy_stage WHERE policy_id = :p AND position > :at"),
                             {"p": policy_id, "at": position}).scalar()
        if later:
            bind.execute(sa.text("UPDATE approval_policy_stage SET fallback = 'skip' WHERE id = :id"), {"id": stage_id})


def downgrade():
    op.get_bind().execute(sa.text(
        "UPDATE approval_policy_stage SET fallback = 'none' WHERE source = 'line_manager' AND fallback = 'skip'"))
