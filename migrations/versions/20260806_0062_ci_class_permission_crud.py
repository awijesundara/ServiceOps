"""Add can_create/can_update/can_delete to ci_class_permission.

Revision ID: 20260806_0062
Revises: 20260806_0061
"""
from alembic import op
import sqlalchemy as sa

revision = "20260806_0062"
down_revision = "20260806_0061"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = [c["name"] for c in sa.inspect(bind).get_columns("ci_class_permission")]
    for name in ("can_create", "can_update", "can_delete"):
        if name not in columns:
            op.add_column(
                "ci_class_permission",
                sa.Column(name, sa.Boolean(), nullable=False, server_default=sa.false()),
            )


def downgrade():
    for name in ("can_create", "can_update", "can_delete"):
        op.drop_column("ci_class_permission", name)
