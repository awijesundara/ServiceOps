"""Mark comments that were drafted by ServiceOps AI and posted by a person.

comment.ai_assisted is set when an operator approves an AI-proposed note,
so the ticket can show it as posted in collaboration with AI and render its
structure. Earlier AI-posted comments are found through their audit record
("ai action execute", details "...; comment=<id>").

Revision ID: 20261003_0109
Revises: 20261002_0108
"""
import re

from alembic import op
import sqlalchemy as sa

revision = "20261003_0109"
down_revision = "20261002_0108"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    bind = op.get_bind()
    existing = {column["name"] for column in sa.inspect(bind).get_columns("comment")}
    if "ai_assisted" not in existing:
        op.add_column("comment", sa.Column(
            "ai_assisted", sa.Boolean(), nullable=False, server_default=sa.false(),
        ))
    rows = bind.execute(sa.text("SELECT details FROM audit WHERE action = 'ai action execute'")).fetchall()
    ids = sorted({int(match.group(1)) for (details,) in rows for match in [re.search(r"comment=(\d+)", details or "")] if match})
    for comment_id in ids:
        bind.execute(sa.text("UPDATE comment SET ai_assisted = :yes WHERE id = :id"), {"yes": True, "id": comment_id})


def downgrade():
    with op.batch_alter_table("comment") as batch:
        batch.drop_column("ai_assisted")
