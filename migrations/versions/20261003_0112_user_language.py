"""Persist a user's offline interface language, defaulting to English.

Revision ID: 20261003_0112
Revises: 20261003_0111
"""
from alembic import op
import sqlalchemy as sa

revision = "20261003_0112"
down_revision = "20261003_0111"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("user_preference")}
    if "language" not in columns:
        op.add_column("user_preference", sa.Column("language", sa.String(16), nullable=False, server_default="en"))


def downgrade():
    with op.batch_alter_table("user_preference") as batch:
        batch.drop_column("language")
