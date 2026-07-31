"""Add support_group_id (owning team) and external_source/external_id to
EnterpriseRecord, so serviceops_core/rt_import.py can import Request
Tracker tickets as IT operations events with a real team owner and
idempotent re-run matching, mirroring the columns Ticket/ConfigurationItem
already have.

Revision ID: 20260731_0040
Revises: 20260731_0039
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0040"
down_revision = "20260731_0039"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "enterprise_record" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("enterprise_record")}
    with op.batch_alter_table("enterprise_record") as batch_op:
        if "support_group_id" not in columns:
            batch_op.add_column(sa.Column("support_group_id", sa.Integer(), nullable=True))
        if "external_source" not in columns:
            batch_op.add_column(sa.Column("external_source", sa.String(length=20), nullable=True))
        if "external_id" not in columns:
            batch_op.add_column(sa.Column("external_id", sa.String(length=120), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "enterprise_record" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("enterprise_record")}
    with op.batch_alter_table("enterprise_record") as batch_op:
        if "external_id" in columns:
            batch_op.drop_column("external_id")
        if "external_source" in columns:
            batch_op.drop_column("external_source")
        if "support_group_id" in columns:
            batch_op.drop_column("support_group_id")
