"""Add signed audit security context and NetBox rack metadata.

Revision ID: 20260904_0085
Revises: 20260904_0084
"""
from alembic import op
import sqlalchemy as sa


revision = "20260904_0085"
down_revision = "20260904_0084"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("audit")}
    if "security_context_json" not in columns:
        op.add_column(
            "audit",
            sa.Column("security_context_json", sa.Text(), nullable=False, server_default="{}"),
        )
    rack_columns = {column["name"] for column in sa.inspect(bind).get_columns("rack")}
    if "attributes_json" not in rack_columns:
        op.add_column(
            "rack",
            sa.Column("attributes_json", sa.Text(), nullable=False, server_default="{}"),
        )


def downgrade():
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("audit")}
    if "security_context_json" in columns:
        op.drop_column("audit", "security_context_json")
    rack_columns = {column["name"] for column in sa.inspect(bind).get_columns("rack")}
    if "attributes_json" in rack_columns:
        op.drop_column("rack", "attributes_json")
