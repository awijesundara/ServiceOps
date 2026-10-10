"""Persist authenticated mobile origin on comments and record activity.

Revision ID: 20261011_0118
Revises: 20261009_0117
"""
from alembic import op
import sqlalchemy as sa

revision = '20261011_0118'
down_revision = '20261009_0117'
branch_labels = None
depends_on = None
serviceops_migration_phase = 'expand'


def upgrade():
    for table in ('comment', 'task_history'):
        if 'source_platform' not in {c['name'] for c in sa.inspect(op.get_bind()).get_columns(table)}:
            op.add_column(table, sa.Column('source_platform', sa.String(30), nullable=True))


def downgrade():
    for table in ('task_history', 'comment'):
        with op.batch_alter_table(table) as batch:
            batch.drop_column('source_platform')
