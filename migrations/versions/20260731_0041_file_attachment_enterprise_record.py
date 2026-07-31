"""Allow FileAttachment to attach to an EnterpriseRecord instead of only a
Ticket, and make ticket_id nullable to match -- needed so
serviceops_core/rt_import.py can import RT's real file attachments (not
just their filenames) onto "IT operations event" records, which have no
Ticket row of their own.

Revision ID: 20260731_0041
Revises: 20260731_0040
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0041"
down_revision = "20260731_0040"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "file_attachment" not in inspector.get_table_names():
        return
    columns = {c["name"]: c for c in inspector.get_columns("file_attachment")}
    with op.batch_alter_table("file_attachment") as batch_op:
        if "enterprise_record_id" not in columns:
            batch_op.add_column(sa.Column("enterprise_record_id", sa.Integer(), nullable=True))
        if columns.get("ticket_id") is not None and not columns["ticket_id"]["nullable"]:
            batch_op.alter_column("ticket_id", existing_type=sa.Integer(), nullable=True)


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "file_attachment" not in inspector.get_table_names():
        return
    columns = {c["name"]: c for c in inspector.get_columns("file_attachment")}
    with op.batch_alter_table("file_attachment") as batch_op:
        if columns.get("ticket_id") is not None and columns["ticket_id"]["nullable"]:
            batch_op.alter_column("ticket_id", existing_type=sa.Integer(), nullable=False)
        if "enterprise_record_id" in columns:
            batch_op.drop_column("enterprise_record_id")
