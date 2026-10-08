"""Index the foreign keys and sort column that every page filters by.

Ticket lists and visibility checks filter tickets by requester/assignee and sort
by updated_at; ticket pages load comments and attachments by ticket; every page
counts the viewer's notifications and pending approval votes; and team
permission checks look up group membership by user. None of these columns was
indexed (PostgreSQL does not index foreign keys automatically), so each lookup
scanned the whole table, which grows with every ticket.

On PostgreSQL the indexes are built CONCURRENTLY so a deploy does not block
writes to large tables; an index that already exists is skipped.

Revision ID: 20261008_0116
Revises: 20261007_0115
"""
from alembic import op
import sqlalchemy as sa

revision = "20261008_0116"
down_revision = "20261007_0115"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

INDEXES = (
    ("ticket", "requester_id"),
    ("ticket", "assignee_id"),
    ("ticket", "updated_at"),
    ("comment", "ticket_id"),
    ("file_attachment", "ticket_id"),
    ("file_attachment", "comment_id"),
    ("notification", "user_id"),
    ("group_member", "user_id"),
    ("approval_vote", "gate_id"),
    ("approval_vote", "approver_id"),
)


def _missing(bind):
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    missing = []
    for table, column in INDEXES:
        if table not in tables:
            continue
        existing = {index["name"] for index in inspector.get_indexes(table)}
        if f"ix_{table}_{column}" not in existing:
            missing.append((table, column))
    return missing


def upgrade():
    bind = op.get_bind()
    missing = _missing(bind)
    if not missing:
        return
    if bind.dialect.name == "postgresql":
        # CREATE INDEX CONCURRENTLY cannot run inside a transaction.
        with op.get_context().autocommit_block():
            for table, column in missing:
                op.create_index(f"ix_{table}_{column}", table, [column], postgresql_concurrently=True, if_not_exists=True)
    else:
        for table, column in missing:
            op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    for table, column in INDEXES:
        if table in tables and f"ix_{table}_{column}" in {index["name"] for index in inspector.get_indexes(table)}:
            op.drop_index(f"ix_{table}_{column}", table_name=table)
