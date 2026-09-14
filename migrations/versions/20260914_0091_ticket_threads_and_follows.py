"""Add threaded replies to Comment and a TicketFollower audience table.

Revision ID: 20260914_0091
Revises: 20260913_0090
"""
from alembic import op
import sqlalchemy as sa

revision = "20260914_0091"
down_revision = "20260913_0090"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    comment_columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("comment")}
    if "parent_id" not in comment_columns:
        op.add_column("comment", sa.Column("parent_id", sa.Integer(), nullable=True))
        op.create_foreign_key(
            "fk_comment_parent_id", "comment", "comment", ["parent_id"], ["id"],
        )
        op.create_index("ix_comment_parent_id", "comment", ["parent_id"])

    inspector = sa.inspect(op.get_bind())
    if "ticket_follower" not in inspector.get_table_names():
        op.create_table(
            "ticket_follower",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("ticket_id", sa.Integer(), sa.ForeignKey("ticket.id"), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("ticket_id", "user_id", name="uq_ticket_follower_ticket_user"),
        )
        op.create_index("ix_ticket_follower_ticket_id", "ticket_follower", ["ticket_id"])
        op.create_index("ix_ticket_follower_user_id", "ticket_follower", ["user_id"])
        op.create_index("ix_ticket_follower_tenant_id", "ticket_follower", ["tenant_id"])


def downgrade():
    # Expand-phase migrations in this project never implement a real
    # downgrade (see 20260911_0089/20260913_0090's identical convention): a
    # rolling deployment can have old and new application code running
    # against the same database simultaneously, and dropping the column/
    # table back out would break whichever code is still mid-request
    # against it.
    pass
