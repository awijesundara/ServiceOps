"""Add configurable outbound integration event subscriptions.

Revision ID: 20260910_0087
Revises: 20260905_0086
"""
from alembic import op
import sqlalchemy as sa

revision = "20260910_0087"
down_revision = "20260905_0086"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("integration_connection")}
    if "event_types_json" not in columns:
        op.add_column(
            "integration_connection",
            sa.Column("event_types_json", sa.Text(), nullable=False, server_default="[]"),
        )
    if "endpoint_encrypted" not in columns:
        op.add_column("integration_connection", sa.Column("endpoint_encrypted", sa.Text()))


def downgrade():
    # Expand migrations are rollback-compatible: old application versions
    # ignore these nullable/defaulted columns. Retaining them avoids destroying
    # subscription policy or encrypted endpoint data during an application
    # rollback; a separately governed contract migration may remove them only
    # after the rollback window closes.
    pass
