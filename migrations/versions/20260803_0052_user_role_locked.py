"""Add user.role_locked so an admin's manual role change survives the
user's next directory/SSO login. Previously provision_external_user()
unconditionally overwrote role from the LDAP-group/team-membership mapping
on every login (see normalize_user_role_from_assignments), silently
reverting a manual agent->manager promotion.

Revision ID: 20260803_0052
Revises: 20260802_0051
"""
from alembic import op
import sqlalchemy as sa

revision = "20260803_0052"
down_revision = "20260802_0051"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = {col["name"] for col in inspector.get_columns("user")}
    if "role_locked" in existing:
        return
    with op.batch_alter_table("user") as batch_op:
        batch_op.add_column(
            sa.Column("role_locked", sa.Boolean(), nullable=False, server_default=sa.false())
        )


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = {col["name"] for col in inspector.get_columns("user")}
    if "role_locked" not in existing:
        return
    with op.batch_alter_table("user") as batch_op:
        batch_op.drop_column("role_locked")
