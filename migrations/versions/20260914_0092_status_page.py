"""Add public status-page opt-in fields and a major-incident update log.

Revision ID: 20260914_0092
Revises: 20260914_0091
"""
from alembic import op
import sqlalchemy as sa

revision = "20260914_0092"
down_revision = "20260914_0091"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    service_columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("service_offering")}
    if "status_page_visible" not in service_columns:
        # Opt-in, defaulting to false: a business service must be explicitly
        # published before an anonymous visitor can see its name or uptime.
        op.add_column(
            "service_offering",
            sa.Column("status_page_visible", sa.Boolean(), nullable=False, server_default=sa.false()),
        )

    profile_columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("major_incident_profile")}
    if "public" not in profile_columns:
        # Same opt-in stance: a major incident's business_impact/communications
        # text is only ever shown on the public page once a coordinator
        # explicitly publishes it via a status update.
        op.add_column(
            "major_incident_profile",
            sa.Column("public", sa.Boolean(), nullable=False, server_default=sa.false()),
        )

    inspector = sa.inspect(op.get_bind())
    if "major_incident_update" not in inspector.get_table_names():
        op.create_table(
            "major_incident_update",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("major_incident_profile_id", sa.Integer(), sa.ForeignKey("major_incident_profile.id"), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("posted_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        )
        op.create_index(
            "ix_major_incident_update_profile_id", "major_incident_update", ["major_incident_profile_id"],
        )
        op.create_index("ix_major_incident_update_tenant_id", "major_incident_update", ["tenant_id"])


def downgrade():
    # Expand-phase migrations in this project never implement a real
    # downgrade (see 20260914_0091's identical convention): a rolling
    # deployment can have old and new application code running against the
    # same database simultaneously, and dropping these back out would break
    # whichever code is still mid-request against them.
    pass
