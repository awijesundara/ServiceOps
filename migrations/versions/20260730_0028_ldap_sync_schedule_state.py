"""Add ldap_sync_state table backing the scheduled LDAP directory sync
(app.process_ldap_sync_schedule / serviceops_core.ldap_sync.sync_directory).
One row per tenant records the last scheduled run so the worker loop can
tell whether a tenant's sync interval has elapsed without ever defaulting
to a global or tenant-1 value (fail-closed, explicit per-tenant iteration).

Revision ID: 20260730_0028
Revises: 20260729_0027
"""
from alembic import op
import sqlalchemy as sa

revision = "20260730_0028"
down_revision = "20260729_0027"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "ldap_sync_state" not in inspector.get_table_names():
        op.create_table(
            "ldap_sync_state",
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), primary_key=True),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_status", sa.String(length=20), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
        )


def downgrade():
    op.drop_table("ldap_sync_state")
