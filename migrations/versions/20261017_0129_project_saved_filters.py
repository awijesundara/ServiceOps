"""Project saved queries and personal favourites (B-450 foundation)."""
from alembic import op
import sqlalchemy as sa

revision = "20261017_0129"
down_revision = "20261016_0128"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    existing=set(sa.inspect(op.get_bind()).get_table_names())
    # The baseline adopts current model metadata on fresh installations.
    # Guard each table independently so fresh and partially adopted schemas work.
    if "project_saved_filter" not in existing:
        op.create_table(
            "project_saved_filter",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
            sa.Column("owner_id", sa.Integer(), sa.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True),
            sa.Column("name", sa.String(100), nullable=False),
            sa.Column("query_text", sa.Text(), nullable=False),
            sa.Column("sharing", sa.String(12), nullable=False, server_default="private"),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("project.id", ondelete="CASCADE"), index=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "owner_id", "name", name="uq_project_filter_owner_name"),
        )
    if "project_filter_favourite" not in existing:
        op.create_table(
            "project_filter_favourite",
            sa.Column("filter_id", sa.Integer(), sa.ForeignKey("project_saved_filter.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
        )


def downgrade():
    op.drop_table("project_filter_favourite")
    op.drop_table("project_saved_filter")
