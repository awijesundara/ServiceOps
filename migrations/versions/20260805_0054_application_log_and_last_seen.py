"""Add application_log (persisted WARNING+ log records -- see
DatabaseLogHandler in app.py -- readable from the admin System Health page
without shell/`docker logs` access) and user.last_seen_at (backs the
"currently active users" stat on the same page).

Revision ID: 20260805_0054
Revises: 20260804_0053
"""
from alembic import op
import sqlalchemy as sa

revision = "20260805_0054"
down_revision = "20260804_0053"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("application_log"):
        op.create_table(
            "application_log",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("level", sa.String(length=10), nullable=False),
            sa.Column("logger_name", sa.String(length=120)),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("traceback", sa.Text()),
            sa.Column("path", sa.String(length=255)),
            sa.Column("method", sa.String(length=10)),
            sa.Column("request_id", sa.String(length=36)),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_application_log_level", "application_log", ["level"])
        op.create_index("ix_application_log_request_id", "application_log", ["request_id"])
        op.create_index("ix_application_log_tenant_id", "application_log", ["tenant_id"])
        op.create_index("ix_application_log_created_at", "application_log", ["created_at"])

    existing_user_columns = {col["name"] for col in inspector.get_columns("user")}
    if "last_seen_at" not in existing_user_columns:
        with op.batch_alter_table("user") as batch_op:
            batch_op.add_column(sa.Column("last_seen_at", sa.DateTime(timezone=True)))


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_user_columns = {col["name"] for col in inspector.get_columns("user")}
    if "last_seen_at" in existing_user_columns:
        with op.batch_alter_table("user") as batch_op:
            batch_op.drop_column("last_seen_at")

    if inspector.has_table("application_log"):
        op.drop_table("application_log")
