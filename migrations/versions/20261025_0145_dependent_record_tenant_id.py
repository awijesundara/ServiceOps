"""Store tenant_id on records that belong to another record.

Tasks, SLAs, history, notes, CI links, assignment groups, profiles,
preferences and grants inherited their tenant only through a parent. This
expand revision adds a nullable, indexed tenant_id to each and backfills it
from the parent, using the same mapping the application applies to new rows
(serviceops_core/dependent_tenancy.py). Rows whose parent no longer exists
stay NULL and are counted in the log. A later contract revision makes the
column NOT NULL once this version has run everywhere. Earlier application
versions ignore the new column.

Platform-wide tables (performance_sample, request_metric_total,
route_rate_limit_window) have no tenant owner and are unchanged.

Revision ID: 20261025_0145
Revises: 20261025_0144
"""
import logging

from alembic import op
import sqlalchemy as sa

revision = "20261025_0145"
down_revision = "20261025_0144"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"
logger = logging.getLogger(__name__)

# table -> (foreign-key column, parent table)
DIRECT = {
    "api_rate_limit_window": ("api_client_id", "api_client"),
    "catalog_task_control": ("task_id", "catalog_task"),
    "change_ownership": ("ticket_id", "ticket"),
    "change_revision": ("ticket_id", "ticket"),
    "checklist_item": ("ticket_id", "ticket"),
    "major_incident_profile": ("ticket_id", "ticket"),
    "ticket_assignment_group": ("ticket_id", "ticket"),
    "external_identity": ("user_id", "user"),
    "favorite": ("user_id", "user"),
    "managed_role_grant": ("user_id", "user"),
    "notification_preference": ("user_id", "user"),
    "recent_view": ("user_id", "user"),
    "user_preference": ("user_id", "user"),
    "user_role_grant": ("user_id", "user"),
    "problem_profile": ("enterprise_record_id", "enterprise_record"),
    "schedule_holiday": ("schedule_id", "business_schedule"),
}

# table -> (type column, id column); operational_task first, others may point at it.
POLYMORPHIC = {
    "operational_task": ("parent_type", "parent_id"),
    "task_ci": ("target_type", "target_id"),
    "task_history": ("target_type", "target_id"),
    "task_note": ("target_type", "target_id"),
    "task_sla": ("target_type", "target_id"),
    "record_link": ("source_type", "source_id"),
}

RECORD_TYPES = {
    "ticket": "ticket",
    "enterprise": "enterprise_record",
    "request": "catalog_request",
    "ritm": "requested_item",
    "catalog_task": "catalog_task",
    "sctask": "catalog_task",
    "operational_task": "operational_task",
    "work_task": "operational_task",
    "ci": "configuration_item",
    "client_ticket": "client_ticket",
    "work_item": "work_item",
    "knowledge": "knowledge",
}

TABLES = (*DIRECT, *POLYMORPHIC)


def _columns(inspector, table):
    return {column["name"] for column in inspector.get_columns(table)}


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    quote = bind.dialect.identifier_preparer.quote
    for table in TABLES:
        if "tenant_id" not in _columns(inspector, table):
            with op.batch_alter_table(table) as batch:
                batch.add_column(sa.Column("tenant_id", sa.Integer(), nullable=True))
                batch.create_foreign_key(f"fk_{table}_tenant_id", "tenant", ["tenant_id"], ["id"])
                batch.create_index(f"ix_{table}_tenant_id", ["tenant_id"])

    for table, (column, parent) in DIRECT.items():
        bind.execute(sa.text(
            f"UPDATE {quote(table)} SET tenant_id = (SELECT p.tenant_id FROM {quote(parent)} p "
            f"WHERE p.id = {quote(table)}.{quote(column)}) WHERE tenant_id IS NULL"
        ))
    for table, (type_column, id_column) in POLYMORPHIC.items():
        for record_type, parent in RECORD_TYPES.items():
            bind.execute(sa.text(
                f"UPDATE {quote(table)} SET tenant_id = (SELECT p.tenant_id FROM {quote(parent)} p "
                f"WHERE p.id = {quote(table)}.{quote(id_column)}) "
                f"WHERE tenant_id IS NULL AND {quote(type_column)} = :record_type"
            ), {"record_type": record_type})

    for table in TABLES:
        missing = bind.execute(sa.text(f"SELECT count(*) FROM {quote(table)} WHERE tenant_id IS NULL")).scalar()
        if missing:
            logger.warning("%s: %d row(s) have no resolvable parent and keep tenant_id NULL", table, missing)


def downgrade():
    inspector = sa.inspect(op.get_bind())
    for table in reversed(TABLES):
        if "tenant_id" in _columns(inspector, table):
            with op.batch_alter_table(table) as batch:
                batch.drop_index(f"ix_{table}_tenant_id")
                # Dropping the column also drops its foreign key (SQLite does not keep its name).
                batch.drop_column("tenant_id")
