"""AI streaming output, visible reasoning steps, and private chat conversations.

Adds progressive-output columns to ai_run (and lets chat turns exist without a
ticket), two admin switches to ai_configuration, and the ai_conversation /
ai_message tables. Every change is additive or relaxes a constraint, so the
previous release keeps working against the new schema during a rollout.

Revision ID: 20260921_0096
Revises: 20260920_0095
"""
from alembic import op
import sqlalchemy as sa

revision = "20260921_0096"
down_revision = "20260920_0095"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

RUN_COLUMNS = (
    ("kind", sa.String(20), "investigation"),
    ("question", sa.Text(), ""),
    ("partial_text", sa.Text(), ""),
    ("reasoning_text", sa.Text(), ""),
    ("steps_json", sa.Text(), "[]"),
)


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    # The historical baseline creates current model metadata on a fresh install, so
    # everything below must tolerate the schema already being present.
    run_columns = {column["name"]: column for column in inspector.get_columns("ai_run")}
    with op.batch_alter_table("ai_run") as batch:
        for name, type_, default in RUN_COLUMNS:
            if name not in run_columns:
                batch.add_column(sa.Column(name, type_, nullable=False, server_default=default))
        if "seq" not in run_columns:
            batch.add_column(sa.Column("seq", sa.Integer(), nullable=False, server_default="0"))
        for name in ("conversation_id", "message_id"):
            if name not in run_columns:
                batch.add_column(sa.Column(name, sa.String(36), nullable=True))
        if "heartbeat_at" not in run_columns:
            batch.add_column(sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
        if not run_columns["ticket_id"]["nullable"]:
            batch.alter_column("ticket_id", existing_type=sa.Integer(), nullable=True)
    run_indexes = {index["name"] for index in sa.inspect(bind).get_indexes("ai_run")}
    if "ix_ai_run_conversation_id" not in run_indexes:
        op.create_index("ix_ai_run_conversation_id", "ai_run", ["conversation_id"])

    config_columns = {column["name"] for column in inspector.get_columns("ai_configuration")}
    with op.batch_alter_table("ai_configuration") as batch:
        if "chat_enabled" not in config_columns:
            batch.add_column(sa.Column("chat_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
        if "show_reasoning" not in config_columns:
            batch.add_column(sa.Column("show_reasoning", sa.Boolean(), nullable=False, server_default=sa.true()))

    if "ai_conversation" not in tables:
        op.create_table(
            "ai_conversation",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("actor_role", sa.String(30), nullable=False),
            sa.Column("title", sa.String(120), nullable=False, server_default="New chat"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_ai_conversation_tenant_id", "ai_conversation", ["tenant_id"])
        op.create_index("ix_ai_conversation_user_id", "ai_conversation", ["user_id"])
    if "ai_message" not in tables:
        op.create_table(
            "ai_message",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("conversation_id", sa.String(36), sa.ForeignKey("ai_conversation.id", ondelete="CASCADE"), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("role", sa.String(12), nullable=False),
            sa.Column("content", sa.Text(), nullable=False, server_default=""),
            sa.Column("reasoning", sa.Text(), nullable=False, server_default=""),
            sa.Column("sources_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("steps_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("status", sa.String(20), nullable=False, server_default="completed"),
            sa.Column("run_id", sa.String(36), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_ai_message_conversation_id", "ai_message", ["conversation_id"])
        op.create_index("ix_ai_message_tenant_id", "ai_message", ["tenant_id"])


def downgrade():
    # Preserve people's conversations and any chat turn: rollback is only allowed
    # before the feature holds data, and needs an explicit archival plan after.
    connection = op.get_bind()
    tables = set(sa.inspect(connection).get_table_names())
    for table in ("ai_message", "ai_conversation"):
        if table in tables and connection.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("AI chat rollback requires an explicit archival plan for existing conversations.")
    if connection.execute(sa.text("SELECT 1 FROM ai_run WHERE kind = 'chat' OR ticket_id IS NULL LIMIT 1")).first():
        raise RuntimeError("AI chat rollback requires an explicit archival plan for existing chat runs.")
    op.drop_table("ai_message")
    op.drop_table("ai_conversation")
    op.drop_index("ix_ai_run_conversation_id", table_name="ai_run")
    with op.batch_alter_table("ai_configuration") as batch:
        batch.drop_column("show_reasoning")
        batch.drop_column("chat_enabled")
    with op.batch_alter_table("ai_run") as batch:
        for name in ("heartbeat_at", "seq", "steps_json", "reasoning_text", "partial_text", "question",
                     "message_id", "conversation_id", "kind"):
            batch.drop_column(name)
        batch.alter_column("ticket_id", existing_type=sa.Integer(), nullable=False)
