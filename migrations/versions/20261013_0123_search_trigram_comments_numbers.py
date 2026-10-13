"""Trigram indexes for the remaining global-search columns.

Global search matches comment bodies, ticket numbers and CI descriptions with
ILIKE '%term%'. Without these indexes each search read every comment (40,000
rows in the 500-user test set) and every ticket row.

Revision ID: 20261013_0123
Revises: 20261013_0122
"""
from alembic import op


revision = "20261013_0123"
down_revision = "20261013_0122"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


SEARCH_INDEXES = {
    "ix_comment_body_trgm": "comment USING gin (body gin_trgm_ops)",
    "ix_ticket_number_trgm": "ticket USING gin (number gin_trgm_ops)",
    "ix_configuration_item_description_trgm": "configuration_item USING gin (description gin_trgm_ops)",
}


def upgrade():
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    for name, target in SEARCH_INDEXES.items():
        op.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {target}")


def downgrade():
    if op.get_bind().dialect.name != "postgresql":
        return
    for name in reversed(SEARCH_INDEXES):
        op.execute(f"DROP INDEX IF EXISTS {name}")
