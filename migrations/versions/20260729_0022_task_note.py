"""Add task_note table for CTASK/PTASK activity and SCTASK/RITM commentary.

Revision ID: 20260729_0022
Revises: 20260729_0021
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_0022"
down_revision = "20260729_0021"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if "task_note" not in sa.inspect(bind).get_table_names():
        op.create_table(
            "task_note",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("target_type", sa.String(length=30), nullable=False),
            sa.Column("target_id", sa.Integer(), nullable=False),
            sa.Column("visibility", sa.String(length=20), nullable=False, server_default="internal"),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_task_note_target_type", "task_note", ["target_type"])
        op.create_index("ix_task_note_target_id", "task_note", ["target_id"])


def downgrade():
    op.drop_index("ix_task_note_target_id", table_name="task_note")
    op.drop_index("ix_task_note_target_type", table_name="task_note")
    op.drop_table("task_note")
