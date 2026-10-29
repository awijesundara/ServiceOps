"""Add notification_preference.email_scope: which notifications are emailed.

"involving_me" (the default and standard): assignments, mentions and
updates to records the user raised or owns. "all": every notification.
Expand only; earlier versions never read the column.

Revision ID: 20261029_0148
Revises: 20261028_0147
"""
from alembic import op
import sqlalchemy as sa

revision = "20261029_0148"
down_revision = "20261028_0147"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("notification_preference")}
    if "email_scope" in columns:
        return  # a new database's baseline already created it from the models
    op.add_column("notification_preference", sa.Column(
        "email_scope", sa.String(length=20), nullable=False, server_default="involving_me"))


def downgrade():
    op.drop_column("notification_preference", "email_scope")
