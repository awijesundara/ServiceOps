"""Adopt the existing ServiceOps schema as the migration baseline.

Revision ID: 20260726_0001
Revises:
"""
from alembic import op
import sqlalchemy as sa

from app import db

revision = "20260726_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """Create a fresh schema or adopt an existing schema without rewriting it."""
    bind = op.get_bind()
    application_tables = set(sa.inspect(bind).get_table_names()) - {"alembic_version"}
    if application_tables:
        required = {"user", "platform_setting", "ticket", "support_group"}
        missing = required - application_tables
        if missing:
            raise RuntimeError(
                "Cannot adopt an incomplete ServiceOps schema; missing tables: "
                + ", ".join(sorted(missing))
            )
        return
    db.metadata.create_all(bind=bind)


def downgrade():
    """The adopted baseline is intentionally non-destructive."""
    raise RuntimeError(
        "The ServiceOps baseline cannot be downgraded destructively. "
        "Restore a validated pre-migration backup to remove the baseline."
    )
