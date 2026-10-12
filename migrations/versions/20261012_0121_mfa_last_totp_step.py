"""Remember the last accepted TOTP time step so a code cannot be replayed.

A TOTP code stays valid for its 30-second step and one step either side, so
without a record of the last step used, an observed code could sign in again
within about 90 seconds. Nullable: existing users have no recorded step and
their next valid code is accepted.

Revision ID: 20261012_0121
Revises: 20261011_0120
"""
from alembic import op
import sqlalchemy as sa

revision = "20261012_0121"
down_revision = "20261011_0120"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    if "mfa_last_totp_step" not in {c["name"] for c in sa.inspect(op.get_bind()).get_columns("user")}:
        op.add_column("user", sa.Column("mfa_last_totp_step", sa.BigInteger(), nullable=True))


def downgrade():
    with op.batch_alter_table("user") as batch:
        batch.drop_column("mfa_last_totp_step")
