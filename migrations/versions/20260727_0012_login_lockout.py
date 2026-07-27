"""Add failed-login lockout tracking to user.

Revision ID: 20260727_0012
Revises: 20260726_0011
"""
from alembic import op
import sqlalchemy as sa

revision = "20260727_0012"
down_revision = "20260726_0011"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    user_columns = {column["name"] for column in inspector.get_columns("user")}
    with op.batch_alter_table("user") as batch:
        if "failed_login_count" not in user_columns:
            batch.add_column(sa.Column(
                "failed_login_count", sa.Integer(), nullable=False, server_default="0",
            ))
        if "locked_until" not in user_columns:
            batch.add_column(sa.Column("locked_until", sa.DateTime(timezone=True)))


def downgrade():
    with op.batch_alter_table("user") as batch:
        batch.drop_column("locked_until")
        batch.drop_column("failed_login_count")
