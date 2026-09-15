"""Add chat_thread_link, mapping an outbound Google Chat message thread back
to the ITIL record it was sent about -- lets a reply typed in that thread
(/ack, /escalate, ...) resolve which record to act on.

Revision ID: 20260915_0093
Revises: 20260914_0092
"""
from alembic import op
import sqlalchemy as sa

revision = "20260915_0093"
down_revision = "20260914_0092"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if "chat_thread_link" not in inspector.get_table_names():
        op.create_table(
            "chat_thread_link",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("connection_id", sa.Integer(), sa.ForeignKey("integration_connection.id"), nullable=False),
            # Google Chat's own thread resource name, e.g.
            # "spaces/AAAA/threads/BBBB" -- unique because exactly one
            # record's alert ever starts a given thread.
            sa.Column("thread_name", sa.String(200), nullable=False, unique=True),
            sa.Column("record_number", sa.String(30), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        )
        op.create_index("ix_chat_thread_link_thread_name", "chat_thread_link", ["thread_name"], unique=True)
        op.create_index("ix_chat_thread_link_tenant_id", "chat_thread_link", ["tenant_id"])


def downgrade():
    # Expand-phase migrations in this project never implement a real
    # downgrade (see 20260914_0092's identical convention): a rolling
    # deployment can have old and new application code running against the
    # same database simultaneously, and dropping this back out would break
    # whichever code is still mid-request against it.
    pass
