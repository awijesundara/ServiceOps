"""The owners of a change's CIs approve it, each person once.

Adds a "CI owner approval" stage (source ci_owners, every owner approves) to
every change approval policy that does not have one, right after its CI owner
team stage (or its owning team stage), so board and executive stages still
come last. Data only: earlier application versions ignore the unknown source,
which resolves to no stage.

Revision ID: 20261020_0137
Revises: 20261020_0136
"""
from alembic import op
import sqlalchemy as sa

revision = "20261020_0137"
down_revision = "20261020_0136"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

NAME = "CI owner approval"


def upgrade():
    bind = op.get_bind()
    policies = bind.execute(sa.text(
        "SELECT id, tenant_id FROM approval_policy WHERE applies_to = 'change'")).fetchall()
    for policy_id, tenant_id in policies:
        stages = bind.execute(sa.text(
            "SELECT id, position, source FROM approval_policy_stage WHERE policy_id = :policy ORDER BY position, id"),
            {"policy": policy_id}).fetchall()
        if any(source == "ci_owners" for _, _, source in stages):
            continue
        anchors = [position for _, position, source in stages if source == "ci_owner_team_managers"] \
            or [position for _, position, source in stages if source == "owning_team_manager"]
        insert_at = (max(anchors) + 1) if anchors else 0
        bind.execute(sa.text(
            "UPDATE approval_policy_stage SET position = position + 1 WHERE policy_id = :policy AND position >= :at"),
            {"policy": policy_id, "at": insert_at})
        bind.execute(sa.text(
            "INSERT INTO approval_policy_stage (tenant_id, policy_id, position, name, source, include_manager, "
            "user_ids_json, mode, condition, fallback, skip_duplicates) VALUES (:tenant, :policy, :position, :name, "
            "'ci_owners', :false, '[]', 'all', 'always', 'none', :false)"),
            {"tenant": tenant_id, "policy": policy_id, "position": insert_at, "name": NAME, "false": False})


def downgrade():
    bind = op.get_bind()
    rows = bind.execute(sa.text(
        "SELECT id, policy_id, position FROM approval_policy_stage WHERE source = 'ci_owners'")).fetchall()
    for stage_id, policy_id, position in rows:
        bind.execute(sa.text("DELETE FROM approval_policy_stage WHERE id = :id"), {"id": stage_id})
        bind.execute(sa.text(
            "UPDATE approval_policy_stage SET position = position - 1 WHERE policy_id = :policy AND position > :at"),
            {"policy": policy_id, "at": position})
