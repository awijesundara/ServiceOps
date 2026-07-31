"""GDPR Article 17 (right to erasure): tracks that a user's personal data
was scrubbed, distinct from the pre-existing `active` deactivation flag --
deactivation alone retains name/email/phone/department indefinitely, which
isn't erasure. See user_erase() in app.py.

Revision ID: 20260731_0048
Revises: 20260731_0047
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0048"
down_revision = "20260731_0047"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("user")}
    if "erased_at" not in columns:
        with op.batch_alter_table("user") as batch_op:
            batch_op.add_column(sa.Column("erased_at", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("user")}
    if "erased_at" in columns:
        with op.batch_alter_table("user") as batch_op:
            batch_op.drop_column("erased_at")
