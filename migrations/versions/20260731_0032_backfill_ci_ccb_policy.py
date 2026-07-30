"""Backfill require_ccb_approval=True on existing CIs that meet the
always-require-CCB policy (Production environment, a Management-class CI,
or Critical business criticality), so previously-created CIs reflect the
same rule newly-created/edited ones now enforce.

Revision ID: 20260731_0032
Revises: 20260731_0031
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0032"
down_revision = "20260731_0031"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = {col["name"] for col in sa.inspect(bind).get_columns("configuration_item")}
    if "require_ccb_approval" not in columns:
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
            )
        )
        .values(require_ccb_approval=True)
    )


def downgrade():
    pass
