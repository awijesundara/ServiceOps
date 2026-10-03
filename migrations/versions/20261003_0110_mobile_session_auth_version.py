"""Bind mobile sessions to the user's credential version.

api_client.auth_version records User.auth_version when a mobile session is
issued; a later password change, reset or deactivation (which bumps
User.auth_version) then ends the session. Existing mobile sessions are
stamped with their user's current version, so they stay valid until the
next credential change instead of all being logged out by the upgrade.

Revision ID: 20261003_0110
Revises: 20261003_0109
"""
from alembic import op
import sqlalchemy as sa

revision = "20261003_0110"
down_revision = "20261003_0109"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    bind = op.get_bind()
    existing = {column["name"] for column in sa.inspect(bind).get_columns("api_client")}
    if "auth_version" not in existing:
        op.add_column("api_client", sa.Column("auth_version", sa.Integer(), nullable=True))
    bind.execute(sa.text(
        'UPDATE api_client SET auth_version = (SELECT "user".auth_version FROM "user" '
        'WHERE "user".id = api_client.acting_user_id) '
        "WHERE client_kind = 'mobile' AND auth_version IS NULL"
    ))


def downgrade():
    with op.batch_alter_table("api_client") as batch:
        batch.drop_column("auth_version")
