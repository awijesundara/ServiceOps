"""Give each group a description and the access levels its members receive.

Revision ID: 20261006_0113
Revises: 20261003_0112
"""
from alembic import op
import sqlalchemy as sa

revision = "20261006_0113"
down_revision = "20261003_0112"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("support_group")}
    if "description" not in columns:
        op.add_column("support_group", sa.Column("description", sa.String(500), nullable=False, server_default=""))
    if "access_roles" not in columns:
        op.add_column("support_group", sa.Column("access_roles", sa.String(80), nullable=False, server_default=""))


def downgrade():
    with op.batch_alter_table("support_group") as batch:
        batch.drop_column("access_roles")
        batch.drop_column("description")
