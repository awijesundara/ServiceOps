"""B-120 guided tours: GuidedTour (admin-authored, versioned, role/route
targeted), GuidedTourStep (ordered step content per tour), UserTourProgress
(per-user dismiss/completion, re-prompted on a version bump).

Revision ID: 20260811_0076
Revises: 20260811_0075
"""
from alembic import op
import sqlalchemy as sa

revision = "20260811_0076"
down_revision = "20260811_0075"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("guided_tour"):
        op.create_table(
            "guided_tour",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("key", sa.String(80), nullable=False),
            sa.Column("title", sa.String(160), nullable=False),
            sa.Column("description", sa.String(500), nullable=False, server_default=""),
            sa.Column("target_route", sa.String(120), nullable=False, server_default="*"),
            sa.Column("target_roles", sa.String(200), nullable=False, server_default=""),
            sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "key", name="uq_guided_tour_tenant_key"),
        )
        op.create_index("ix_guided_tour_tenant_id", "guided_tour", ["tenant_id"])

    if not inspector.has_table("guided_tour_step"):
        op.create_table(
            "guided_tour_step",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("tour_id", sa.Integer(), sa.ForeignKey("guided_tour.id"), nullable=False),
            sa.Column("step_order", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("target_selector", sa.String(300), nullable=False, server_default=""),
            sa.Column("title", sa.String(160), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("placement", sa.String(20), nullable=False, server_default="bottom"),
        )
        op.create_index("ix_guided_tour_step_tenant_id", "guided_tour_step", ["tenant_id"])
        op.create_index("ix_guided_tour_step_tour_id", "guided_tour_step", ["tour_id"])

    if not inspector.has_table("user_tour_progress"):
        op.create_table(
            "user_tour_progress",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("tour_id", sa.Integer(), sa.ForeignKey("guided_tour.id"), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="dismissed"),
            sa.Column("tour_version_seen", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("user_id", "tour_id", name="uq_user_tour_progress_user_tour"),
        )
        op.create_index("ix_user_tour_progress_tenant_id", "user_tour_progress", ["tenant_id"])
        op.create_index("ix_user_tour_progress_user_id", "user_tour_progress", ["user_id"])
        op.create_index("ix_user_tour_progress_tour_id", "user_tour_progress", ["tour_id"])


def downgrade():
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("user_tour_progress"):
        op.drop_table("user_tour_progress")
    if inspector.has_table("guided_tour_step"):
        op.drop_table("guided_tour_step")
    if inspector.has_table("guided_tour"):
        op.drop_table("guided_tour")
