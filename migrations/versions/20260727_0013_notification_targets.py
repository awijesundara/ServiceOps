"""Add target_type/target_id to notification so entries can link to their source record.

Revision ID: 20260727_0013
Revises: 20260727_0012
"""
from alembic import op
import sqlalchemy as sa

revision = "20260727_0013"
down_revision = "20260727_0012"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("notification")}
    with op.batch_alter_table("notification") as batch:
        if "target_type" not in columns:
            batch.add_column(sa.Column("target_type", sa.String(30)))
        if "target_id" not in columns:
            batch.add_column(sa.Column("target_id", sa.Integer()))


def downgrade():
    with op.batch_alter_table("notification") as batch:
        batch.drop_column("target_id")
        batch.drop_column("target_type")
