"""Add ci_relationship.label for port-level LLDP connection detail.

Revision ID: 20260806_0061
Revises: 20260806_0060
"""
from alembic import op
import sqlalchemy as sa

revision = "20260806_0061"
down_revision = "20260806_0060"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = [c["name"] for c in sa.inspect(bind).get_columns("ci_relationship")]
    if "label" not in columns:
        op.add_column("ci_relationship", sa.Column("label", sa.String(160)))


def downgrade():
    op.drop_column("ci_relationship", "label")
