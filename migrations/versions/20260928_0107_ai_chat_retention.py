"""Retention period for AI chat history.

ai_configuration.retention_days already limits how long investigation and chat
run records are kept, but chat conversations themselves (questions, answers and
cited sources) were kept until the person deleted them. chat_retention_days
deletes a conversation that many days after its last message; 30 by default.

Revision ID: 20260928_0107
Revises: 20260927_0106
"""
from alembic import op
import sqlalchemy as sa

revision = "20260928_0107"
down_revision = "20260927_0106"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("ai_configuration")}
    if "chat_retention_days" not in existing:
        op.add_column("ai_configuration", sa.Column("chat_retention_days", sa.Integer(), nullable=False,
                                                    server_default="30"))


def downgrade():
    with op.batch_alter_table("ai_configuration") as batch:
        batch.drop_column("chat_retention_days")
