"""Re-run the always-require-CCB backfill (20260731_0032) now that
environment values are normalized (20260731_0034) and the Management-class
match also recognizes "mgmt", not just "management" (app.py's
ci_class_is_management). 20260731_0032 ran before normalization, so a CI
stored as "Prod" instead of "Production" was missed the first time.

Revision ID: 20260731_0035
Revises: 20260731_0034
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0035"
down_revision = "20260731_0034"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if "configuration_item" not in sa.inspect(bind).get_table_names():
        return
    ci = sa.table(
        "configuration_item",
        sa.column("id", sa.Integer),
        sa.column("environment", sa.String),
        sa.column("ci_class", sa.String),
        sa.column("business_criticality", sa.String),
        sa.column("require_ccb_approval", sa.Boolean),
    )
    bind.execute(
        ci.update()
        .where(
            sa.or_(
                ci.c.environment == "Production",
                ci.c.business_criticality == "Critical",
                sa.func.lower(ci.c.ci_class).contains("management"),
                sa.func.lower(ci.c.ci_class).contains("mgmt"),
            )
        )
        .values(require_ccb_approval=True)
    )


def downgrade():
    pass
