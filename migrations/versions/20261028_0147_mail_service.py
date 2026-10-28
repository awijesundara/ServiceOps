"""Add mail_service: the saved ways of sending email, one default and an optional fallback.

Expand only: a new table that earlier versions never read. While it is
empty the application keeps sending with the email platform settings, so
the upgrade changes nothing until an administrator saves a service.

Revision ID: 20261028_0147
Revises: 20261027_0146
"""
from alembic import op
import sqlalchemy as sa

revision = "20261028_0147"
down_revision = "20261027_0146"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    if "mail_service" in sa.inspect(op.get_bind()).get_table_names():
        return  # a new database's baseline already created it from the models
    op.create_table(
        "mail_service",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("config_encrypted", sa.Text(), nullable=False, server_default=""),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_fallback", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_tested_at", sa.DateTime(timezone=True)),
        sa.Column("last_test_ok", sa.Boolean()),
        sa.Column("last_test_message", sa.String(length=600)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(length=600)),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_mail_service_tenant_id", "mail_service", ["tenant_id"])


def downgrade():
    op.drop_index("ix_mail_service_tenant_id", table_name="mail_service")
    op.drop_table("mail_service")
