"""Add a per-AI-service outbound proxy policy.

Revision ID: 20260925_0102
Revises: 20260925_0101
"""
from alembic import op
import sqlalchemy as sa

revision = "20260925_0102"
down_revision = "20260925_0101"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("ai_connection")}
    if "proxy_mode" not in columns:
        op.add_column("ai_connection", sa.Column("proxy_mode", sa.String(12), nullable=False,
                                                 server_default="default"))
    if "proxy_url_encrypted" not in columns:
        op.add_column("ai_connection", sa.Column("proxy_url_encrypted", sa.Text(), nullable=False,
                                                 server_default=""))


def downgrade():
    with op.batch_alter_table("ai_connection") as batch:
        batch.drop_column("proxy_url_encrypted")
        batch.drop_column("proxy_mode")
