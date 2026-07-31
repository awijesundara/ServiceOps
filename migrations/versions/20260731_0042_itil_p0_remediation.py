"""ITIL 4 gap-analysis P0 remediation: continual improvement register
(ImprovementItem), change post-implementation review
(ChangePostImplementationReview), and CI-to-service mapping
(ServiceOfferingCI).

Revision ID: 20260731_0042
Revises: 20260731_0041
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0042"
down_revision = "20260731_0041"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if "improvement_item" not in existing:
        op.create_table(
            "improvement_item",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("number", sa.String(length=20), nullable=False, unique=True),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("source_type", sa.String(length=20), nullable=True),
            sa.Column("source_id", sa.Integer(), nullable=True),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="Identified"),
            sa.Column("expected_outcome", sa.Text(), nullable=True),
            sa.Column("measured_result", sa.Text(), nullable=True),
            sa.Column("owner_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=True),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        )
        op.create_index("ix_improvement_item_tenant_id", "improvement_item", ["tenant_id"])

    if "change_post_implementation_review" not in existing:
        op.create_table(
            "change_post_implementation_review",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("ticket_id", sa.Integer(), sa.ForeignKey("ticket.id"), nullable=False, unique=True),
            sa.Column("outcome", sa.String(length=30), nullable=False),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("follow_up_actions", sa.Text(), nullable=True),
            sa.Column("reviewed_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        )
        op.create_index(
            "ix_change_pir_tenant_id", "change_post_implementation_review", ["tenant_id"]
        )

    if "service_offering_ci" not in existing:
        op.create_table(
            "service_offering_ci",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("service_offering_id", sa.Integer(), sa.ForeignKey("service_offering.id"), nullable=False),
            sa.Column("ci_id", sa.Integer(), sa.ForeignKey("configuration_item.id"), nullable=False),
            sa.Column("relationship_role", sa.String(length=30), nullable=False, server_default="Supporting"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.UniqueConstraint("service_offering_id", "ci_id", name="uq_service_offering_ci"),
        )
        op.create_index("ix_service_offering_ci_tenant_id", "service_offering_ci", ["tenant_id"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())
    if "service_offering_ci" in existing:
        op.drop_table("service_offering_ci")
    if "change_post_implementation_review" in existing:
        op.drop_table("change_post_implementation_review")
    if "improvement_item" in existing:
        op.drop_table("improvement_item")
