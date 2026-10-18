"""Project sprint lifecycle, membership and append-only scope snapshots."""
from alembic import op
import sqlalchemy as sa

revision = '20261017_0130'
down_revision = '20261017_0129'
branch_labels = None
depends_on = None
serviceops_migration_phase = 'expand'


def upgrade():
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if 'project_sprint' not in existing:
        op.create_table('project_sprint',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('project_id', sa.Integer(), sa.ForeignKey('project.id', ondelete='CASCADE'), nullable=False, index=True),
            sa.Column('name', sa.String(100), nullable=False), sa.Column('goal', sa.Text(), nullable=False),
            sa.Column('state', sa.String(12), nullable=False),
            sa.Column('start_at', sa.DateTime(timezone=True)), sa.Column('end_at', sa.DateTime(timezone=True)),
            sa.Column('started_at', sa.DateTime(timezone=True)), sa.Column('completed_at', sa.DateTime(timezone=True)),
            sa.Column('created_by_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('baseline_json', sa.Text(), nullable=False), sa.Column('outcome_json', sa.Text(), nullable=False),
            sa.CheckConstraint("state IN ('planned','active','closed')", name='ck_project_sprint_state'))
    if 'project_sprint_item' not in existing:
        op.create_table('project_sprint_item',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('sprint_id', sa.Integer(), sa.ForeignKey('project_sprint.id', ondelete='CASCADE'), nullable=False, index=True),
            sa.Column('work_item_id', sa.Integer(), sa.ForeignKey('work_item.id', ondelete='SET NULL'), index=True),
            sa.Column('item_key', sa.String(32), nullable=False), sa.Column('title', sa.String(255), nullable=False),
            sa.Column('active', sa.Boolean(), nullable=False), sa.Column('completed', sa.Boolean(), nullable=False),
            sa.Column('added_at', sa.DateTime(timezone=True), nullable=False), sa.Column('removed_at', sa.DateTime(timezone=True)))
        op.create_index('uq_project_sprint_item_current', 'project_sprint_item', ['work_item_id'], unique=True,
                        postgresql_where=sa.text('active'), sqlite_where=sa.text('active = 1'))
    if 'project_sprint_event' not in existing:
        op.create_table('project_sprint_event',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('sprint_id', sa.Integer(), sa.ForeignKey('project_sprint.id', ondelete='CASCADE'), nullable=False, index=True),
            sa.Column('membership_id', sa.Integer(), sa.ForeignKey('project_sprint_item.id', ondelete='CASCADE')),
            sa.Column('actor_id', sa.Integer(), sa.ForeignKey('user.id')),
            sa.Column('kind', sa.String(24), nullable=False), sa.Column('payload_json', sa.Text(), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))
        op.create_index('ix_project_sprint_event_time', 'project_sprint_event', ['sprint_id', 'created_at', 'id'])


def downgrade():
    op.drop_table('project_sprint_event')
    op.drop_table('project_sprint_item')
    op.drop_table('project_sprint')
