"""Per-field public profile visibility on user preferences.

Revision ID: 20261011_0120
Revises: 20261011_0119
"""
from alembic import op
import sqlalchemy as sa

revision = "20261011_0120"
down_revision = "20261011_0119"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("user_preference")}
    if "profile_visibility_json" not in columns:
        op.add_column("user_preference", sa.Column("profile_visibility_json", sa.Text(), nullable=True))


def downgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("user_preference")}
    if "profile_visibility_json" in columns:
        with op.batch_alter_table("user_preference") as batch:
            batch.drop_column("profile_visibility_json")
