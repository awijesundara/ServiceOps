"""Add require_ccb_approval to configuration_item: a per-CI override that
forces CCB authorization on changes even when the CI's environment isn't in
the CCB_REQUIRED_ENVIRONMENTS setting (e.g. a Dev box that still needs board
sign-off in custom cases).

Revision ID: 20260731_0030
Revises: 20260730_0029
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0030"
down_revision = "20260730_0029"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = {col["name"] for col in sa.inspect(bind).get_columns("configuration_item")}
    with op.batch_alter_table("configuration_item") as batch:
        if "require_ccb_approval" not in columns:
            batch.add_column(sa.Column(
                "require_ccb_approval", sa.Boolean(), nullable=False,
                server_default=sa.false(),
            ))


def downgrade():
    with op.batch_alter_table("configuration_item") as batch:
        batch.drop_column("require_ccb_approval")
