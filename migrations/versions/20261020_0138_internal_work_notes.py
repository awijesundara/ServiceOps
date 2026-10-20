"""Internal work notes: a ticket comment the caller does not see.

Revision ID: 20261020_0138
Revises: 20261020_0137
"""
from alembic import op
import sqlalchemy as sa

revision = "20261020_0138"
down_revision = "20261020_0137"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("comment")}
    if "internal" not in existing:
        # Every existing comment stays visible as before.
        op.add_column("comment", sa.Column("internal", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    with op.batch_alter_table("comment") as batch:
        batch.drop_column("internal")
