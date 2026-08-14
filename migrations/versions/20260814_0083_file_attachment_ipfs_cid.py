"""Add file_attachment.ipfs_cid for the optional database-less
(STORAGE_MODE=ipfs) deployment mode's file-attachment storage. Null under
the default PostgreSQL mode.

Revision ID: 20260814_0083
Revises: 20260814_0082
"""
from alembic import op
import sqlalchemy as sa

revision = "20260814_0083"
down_revision = "20260814_0082"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = {col["name"] for col in inspector.get_columns("file_attachment")}
    if "ipfs_cid" in existing:
        return
    with op.batch_alter_table("file_attachment") as batch_op:
        batch_op.add_column(sa.Column("ipfs_cid", sa.String(length=120), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = {col["name"] for col in inspector.get_columns("file_attachment")}
    if "ipfs_cid" not in existing:
        return
    with op.batch_alter_table("file_attachment") as batch_op:
        batch_op.drop_column("ipfs_cid")
