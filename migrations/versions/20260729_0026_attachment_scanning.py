"""Add sha256 and scan_status to file_attachment, backing the required
"cryptographic attachment hashes" and "malware scanning or quarantine adapter"
controls (CLAUDE.md Security requirements). scan_status defaults to
'not_scanned' for existing rows uploaded before this pass — that is an honest
statement of fact, not a claim they were checked.

Revision ID: 20260729_0026
Revises: 20260729_0025
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_0026"
down_revision = "20260729_0025"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = {col["name"] for col in sa.inspect(bind).get_columns("file_attachment")}
    if "sha256" not in columns:
        op.add_column("file_attachment", sa.Column("sha256", sa.String(length=64), nullable=True))
    if "scan_status" not in columns:
        op.add_column("file_attachment", sa.Column(
            "scan_status", sa.String(length=20), nullable=False, server_default="not_scanned",
        ))


def downgrade():
    with op.batch_alter_table("file_attachment") as batch:
        batch.drop_column("scan_status")
        batch.drop_column("sha256")
