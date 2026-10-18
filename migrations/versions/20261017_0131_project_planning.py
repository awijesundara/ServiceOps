"""Persistent planning drafts, project goals and personal view settings."""
from alembic import op
import sqlalchemy as sa

revision = '20261017_0131'
down_revision = '20261017_0130'
branch_labels = None
depends_on = None
serviceops_migration_phase = 'expand'


def upgrade():
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if 'project_planning_draft' not in existing:
        op.create_table('project_planning_draft',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('owner_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False, index=True),
            sa.Column('name', sa.String(100), nullable=False), sa.Column('payload_json', sa.Text(), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False), sa.Column('applied_at', sa.DateTime(timezone=True)))
    if 'project_view_preference' not in existing:
        op.create_table('project_view_preference',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('project_id', sa.Integer(), sa.ForeignKey('project.id', ondelete='CASCADE'), nullable=False),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False),
            sa.Column('payload_json', sa.Text(), nullable=False),
            sa.UniqueConstraint('project_id', 'user_id', name='uq_project_view_preference'))
    if 'project_goal' not in existing:
        op.create_table('project_goal',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('project_id', sa.Integer(), sa.ForeignKey('project.id', ondelete='CASCADE'), nullable=False, index=True),
            sa.Column('title', sa.String(160), nullable=False), sa.Column('description', sa.Text(), nullable=False),
            sa.Column('target_date', sa.Date()), sa.Column('state', sa.String(12), nullable=False),
            sa.Column('created_by_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.CheckConstraint("state IN ('open','achieved','cancelled')", name='ck_project_goal_state'))
    if 'project_goal_item' not in existing:
        op.create_table('project_goal_item',
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('goal_id', sa.Integer(), sa.ForeignKey('project_goal.id', ondelete='CASCADE'), primary_key=True),
            sa.Column('work_item_id', sa.Integer(), sa.ForeignKey('work_item.id', ondelete='CASCADE'), primary_key=True))


def downgrade():
    op.drop_table('project_goal_item')
    op.drop_table('project_goal')
    op.drop_table('project_view_preference')
    op.drop_table('project_planning_draft')
