"""Add credential rotation session version.

Revision ID: 20260726_0010
Revises: 20260726_0009
"""
from alembic import op
import sqlalchemy as sa

revision = "20260726_0010"
down_revision = "20260726_0009"
branch_labels = None
depends_on = None


def upgrade():
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("user")}
    if "auth_version" not in columns:
        with op.batch_alter_table("user") as batch:
            batch.add_column(sa.Column(
                "auth_version", sa.Integer(), nullable=False, server_default="1"
            ))


def downgrade():
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("user")}
    if "auth_version" in columns:
        with op.batch_alter_table("user") as batch:
            batch.drop_column("auth_version")
