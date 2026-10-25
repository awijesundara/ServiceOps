"""Index the foreign keys that service impact, CI topology, request pages and
search join on. PostgreSQL does not index foreign keys itself, so these
lookups scanned their tables: services for a CI (the unique key leads with
service_offering_id), records touching a CI, a request's items and their
tasks, a CI's parents, an enterprise record's approvals and a service's
tickets. Additive only; earlier application versions are unaffected.

Revision ID: 20261025_0144
Revises: 20261023_0143
"""
from alembic import op
import sqlalchemy as sa

revision = "20261025_0144"
down_revision = "20261023_0143"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

INDEXES = (
    ("service_offering_ci", "ci_id"),
    ("task_ci", "ci_id"),
    ("requested_item", "request_id"),
    ("catalog_task", "requested_item_id"),
    ("ci_relationship", "child_id"),
    ("approval", "enterprise_record_id"),
    ("ticket", "service_offering_id"),
)


def _existing(inspector, table):
    return {index["name"] for index in inspector.get_indexes(table)}


def upgrade():
    inspector = sa.inspect(op.get_bind())
    for table, column in INDEXES:
        name = f"ix_{table}_{column}"
        if name not in _existing(inspector, table):
            op.create_index(name, table, [column])


def downgrade():
    inspector = sa.inspect(op.get_bind())
    for table, column in reversed(INDEXES):
        name = f"ix_{table}_{column}"
        if name in _existing(inspector, table):
            op.drop_index(name, table_name=table)
