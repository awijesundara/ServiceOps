"""Add division, employee_id, employee_type to user, backing the generic LDAP
directory sync (serviceops_core/ldap_sync.py) that populates profile fields,
manager chain, and AD-group team membership from an existing directory
without any hard-coded company/domain assumptions. All three columns are
nullable: LDAP entries are commonly sparse and existing users pre-date this
sync entirely, so nothing should be forced non-null retroactively.

Revision ID: 20260729_0027
Revises: 20260729_0026
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_0027"
down_revision = "20260729_0026"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = {col["name"] for col in sa.inspect(bind).get_columns("user")}
    with op.batch_alter_table("user") as batch:
        if "division" not in columns:
            batch.add_column(sa.Column("division", sa.String(length=120), nullable=True))
        if "employee_id" not in columns:
            batch.add_column(sa.Column("employee_id", sa.String(length=80), nullable=True))
        if "employee_type" not in columns:
            batch.add_column(sa.Column("employee_type", sa.String(length=80), nullable=True))


def downgrade():
    with op.batch_alter_table("user") as batch:
        batch.drop_column("employee_type")
        batch.drop_column("employee_id")
        batch.drop_column("division")
