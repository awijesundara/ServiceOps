"""Enforce one link per group for tenant-wide approval authorities.

uq_approval_authority_group includes the nullable subject_group_id, and
both PostgreSQL and SQLite treat NULLs as distinct, so the CCB, executive
and enterprise authorities (subject NULL) could hold the same group twice.
Duplicate links are removed first (keeping the oldest); they never changed
who was asked to approve, because members are resolved as a set.

Revision ID: 20261011_0119
Revises: 20261011_0118
"""
from alembic import op
import sqlalchemy as sa

revision = "20261011_0119"
down_revision = "20261011_0118"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

INDEX = "uq_approval_authority_group_tenant_wide"


def upgrade():
    bind = op.get_bind()
    if INDEX in {index["name"] for index in sa.inspect(bind).get_indexes("approval_authority_group")}:
        return
    op.execute(sa.text(
        "DELETE FROM approval_authority_group WHERE subject_group_id IS NULL AND id NOT IN ("
        " SELECT keep_id FROM (SELECT MIN(id) AS keep_id FROM approval_authority_group"
        " WHERE subject_group_id IS NULL GROUP BY tenant_id, authority, group_id) AS kept)"
    ))
    op.create_index(
        INDEX, "approval_authority_group", ["tenant_id", "authority", "group_id"], unique=True,
        sqlite_where=sa.text("subject_group_id IS NULL"),
        postgresql_where=sa.text("subject_group_id IS NULL"),
    )


def downgrade():
    op.drop_index(INDEX, table_name="approval_authority_group")
