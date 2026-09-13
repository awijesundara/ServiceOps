"""Add a severity column to Notification for bell-icon color/animation.

Revision ID: 20260913_0090
Revises: 20260911_0089
"""
from alembic import op
import sqlalchemy as sa

revision = "20260913_0090"
down_revision = "20260911_0089"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("notification")}
    if "severity" not in columns:
        # No index: only three distinct values ever exist (critical/warning/
        # info) and every read of this column is already scoped by the
        # existing user_id/tenant_id/read filters on notification's own
        # query paths, so a dedicated index would add write overhead for
        # negligible read benefit.
        op.add_column(
            "notification",
            sa.Column("severity", sa.String(10), nullable=False, server_default="info"),
        )


def downgrade():
    # Expand-phase migrations in this project never implement a real
    # downgrade (see 20260911_0089's identical convention): a rolling
    # deployment can have old and new application code running against the
    # same database simultaneously, and yanking the column back out would
    # break whichever code is still mid-request against it. The column is
    # retained; a future contract-phase migration removes it once no
    # supported application version still reads/writes it.
    pass
