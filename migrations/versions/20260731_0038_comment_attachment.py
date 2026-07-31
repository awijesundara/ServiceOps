"""Let a file attachment be linked to a specific comment (work note), not
just the ticket as a whole -- so staff can attach a screenshot/log directly
to the note they're posting instead of using a separate Attachments panel.

Revision ID: 20260731_0038
Revises: 20260731_0037
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0038"
down_revision = "20260731_0037"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "file_attachment" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("file_attachment")}
    if "comment_id" in columns:
        return
    with op.batch_alter_table("file_attachment") as batch_op:
        batch_op.add_column(sa.Column("comment_id", sa.Integer(), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "file_attachment" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("file_attachment")}
    if "comment_id" not in columns:
        return
    with op.batch_alter_table("file_attachment") as batch_op:
        batch_op.drop_column("comment_id")
