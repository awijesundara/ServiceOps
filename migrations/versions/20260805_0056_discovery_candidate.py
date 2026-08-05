"""Add discovery_candidate (staged discovery results awaiting admin review
-- see DiscoveryCandidate in app.py). Discovery runs no longer create a CI
directly; they stage candidates here and an explicit "Add selected"/"Add
all"/"Discard" decision on the review page is what calls
reconcile_facts_into_cmdb.

Revision ID: 20260805_0056
Revises: 20260805_0055
"""
from alembic import op
import sqlalchemy as sa

revision = "20260805_0056"
down_revision = "20260805_0055"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("discovery_candidate"):
        op.create_table(
            "discovery_candidate",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("target_id", sa.Integer(), sa.ForeignKey("discovery_target.id"), nullable=False),
            sa.Column("host", sa.String(length=80), nullable=False),
            sa.Column("name", sa.String(length=160), nullable=False),
            sa.Column("ci_class", sa.String(length=80), nullable=False),
            sa.Column("vendor", sa.String(length=120)),
            sa.Column("discovery_source", sa.String(length=40), nullable=False),
            sa.Column("facts", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        )
        op.create_index("ix_discovery_candidate_tenant_id", "discovery_candidate", ["tenant_id"])
        op.create_index("ix_discovery_candidate_target_id", "discovery_candidate", ["target_id"])


def downgrade():
    op.drop_index("ix_discovery_candidate_target_id", table_name="discovery_candidate")
    op.drop_index("ix_discovery_candidate_tenant_id", table_name="discovery_candidate")
    op.drop_table("discovery_candidate")
