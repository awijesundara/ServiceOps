"""Add user profile picture path and location field.

Revision ID: 20260729_0017
Revises: 20260728_0016
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_0017"
down_revision = "20260728_0016"
branch_labels = None
depends_on = None


def _add_missing(table, definitions):
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns(table)}
    with op.batch_alter_table(table) as batch:
        for name, column in definitions:
            if name not in columns:
                batch.add_column(column)


def upgrade():
    _add_missing("user", [
        ("avatar_path", sa.Column("avatar_path", sa.String(255), nullable=True)),
        ("location", sa.Column("location", sa.String(120), nullable=False, server_default="")),
    ])


def downgrade():
    with op.batch_alter_table("user") as batch:
        for name in ["location", "avatar_path"]:
            batch.drop_column(name)
