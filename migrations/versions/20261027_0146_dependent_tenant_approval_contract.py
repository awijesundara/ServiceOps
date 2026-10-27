"""Backfill tenant_id on dependent rows that point at approval chains or contracts.

Revision 20261025_0145 backfilled tenant_id from every parent record type
except approval chains and contracts, which also own history and notes.
This expand revision fills those rows from their parent. Rows whose parent
no longer exists stay NULL. Downgrade is a no-op: the column belongs to
20261025_0145 and earlier versions ignore its values.

Revision ID: 20261027_0146
Revises: 20261025_0145
"""
from alembic import op
import sqlalchemy as sa

revision = "20261027_0146"
down_revision = "20261025_0145"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

POLYMORPHIC = {
    "operational_task": ("parent_type", "parent_id"),
    "task_ci": ("target_type", "target_id"),
    "task_history": ("target_type", "target_id"),
    "task_note": ("target_type", "target_id"),
    "task_sla": ("target_type", "target_id"),
    "record_link": ("source_type", "source_id"),
}
RECORD_TYPES = {"approval_chain": "approval_chain", "contract": "contract"}


def upgrade():
    bind = op.get_bind()
    quote = bind.dialect.identifier_preparer.quote
    for table, (type_column, id_column) in POLYMORPHIC.items():
        for record_type, parent in RECORD_TYPES.items():
            bind.execute(sa.text(
                f"UPDATE {quote(table)} SET tenant_id = (SELECT p.tenant_id FROM {quote(parent)} p "
                f"WHERE p.id = {quote(table)}.{quote(id_column)}) "
                f"WHERE tenant_id IS NULL AND {quote(type_column)} = :record_type"
            ), {"record_type": record_type})


def downgrade():
    pass
