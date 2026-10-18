"""Saved plans, portfolio structure, program allocations and audited automation."""
from alembic import op
import sqlalchemy as sa

revision = '20261018_0132'
down_revision = '20261017_0131'
branch_labels = None
depends_on = None
serviceops_migration_phase = 'expand'


def upgrade():
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if 'project_plan' not in existing:
        op.create_table('project_plan',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('owner_id', sa.Integer, sa.ForeignKey('user.id'), nullable=False),
            sa.Column('name', sa.String(100), nullable=False),
            sa.Column('description', sa.Text, nullable=False),
            sa.Column('projects_json', sa.Text, nullable=False),
            sa.Column('settings_json', sa.Text, nullable=False),
            sa.Column('revision', sa.Integer, nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False))
    if 'project_plan_node' not in existing:
        op.create_table('project_plan_node',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('plan_id', sa.Integer, sa.ForeignKey('project_plan.id', ondelete='CASCADE'), nullable=False, index=True),
            sa.Column('parent_id', sa.Integer, sa.ForeignKey('project_plan_node.id', ondelete='CASCADE')),
            sa.Column('name', sa.String(160), nullable=False),
            sa.Column('kind', sa.String(40), nullable=False),
            sa.Column('position', sa.Integer, nullable=False),
            sa.Column('item_keys_json', sa.Text, nullable=False))
    if 'project_plan_team' not in existing:
        op.create_table('project_plan_team',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('plan_id', sa.Integer, sa.ForeignKey('project_plan.id', ondelete='CASCADE'), nullable=False, index=True),
            sa.Column('name', sa.String(100), nullable=False),
            sa.Column('capacity', sa.Float, nullable=False),
            sa.Column('unit', sa.String(10), nullable=False),
            sa.Column('members_json', sa.Text, nullable=False),
            sa.CheckConstraint("capacity >= 0 AND unit IN ('hours','points')", name='ck_project_plan_team_capacity'))
    if 'project_plan_allocation' not in existing:
        op.create_table('project_plan_allocation',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('plan_id', sa.Integer, sa.ForeignKey('project_plan.id', ondelete='CASCADE'), nullable=False, index=True),
            sa.Column('team_id', sa.Integer, sa.ForeignKey('project_plan_team.id', ondelete='CASCADE'), nullable=False),
            sa.Column('work_item_id', sa.Integer, sa.ForeignKey('work_item.id', ondelete='CASCADE'), nullable=False),
            sa.Column('iteration', sa.Integer, nullable=False),
            sa.UniqueConstraint('plan_id', 'work_item_id', name='uq_plan_work_allocation'),
            sa.CheckConstraint('iteration >= 0 AND iteration < 52', name='ck_plan_iteration'))
    if 'project_plan_scenario' not in existing:
        op.create_table('project_plan_scenario',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('plan_id', sa.Integer, sa.ForeignKey('project_plan.id', ondelete='CASCADE'), nullable=False, index=True),
            sa.Column('name', sa.String(100), nullable=False),
            sa.Column('payload_json', sa.Text, nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))
    if 'project_automation_rule' not in existing:
        op.create_table('project_automation_rule',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('owner_id', sa.Integer, sa.ForeignKey('user.id'), nullable=False),
            sa.Column('name', sa.String(100), nullable=False),
            sa.Column('enabled', sa.Boolean, nullable=False),
            sa.Column('projects_json', sa.Text, nullable=False),
            sa.Column('config_json', sa.Text, nullable=False),
            sa.Column('revision', sa.Integer, nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))
    if 'project_automation_run' not in existing:
        op.create_table('project_automation_run',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenant.id'), nullable=False, index=True),
            sa.Column('rule_id', sa.Integer, sa.ForeignKey('project_automation_rule.id', ondelete='CASCADE'), nullable=False, index=True),
            sa.Column('work_item_id', sa.Integer, sa.ForeignKey('work_item.id', ondelete='SET NULL')),
            sa.Column('item_key', sa.String(32), nullable=False),
            sa.Column('outcome', sa.String(20), nullable=False),
            sa.Column('affected', sa.Integer, nullable=False),
            sa.Column('detail', sa.String(160), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))

    if 'project_sandbox' not in existing:
        op.create_table('project_sandbox',
            sa.Column('slot',sa.Integer(),nullable=False),
            sa.Column('id',sa.Integer(),primary_key=True),
            sa.Column('tenant_id',sa.Integer(),sa.ForeignKey('tenant.id'),nullable=False,index=True),
            sa.Column('owner_id',sa.Integer(),sa.ForeignKey('user.id'),nullable=False),
            sa.Column('name',sa.String(100),nullable=False),sa.Column('state',sa.String(16),nullable=False),
            sa.Column('image',sa.String(255)),sa.Column('last_error',sa.String(160),nullable=False),
            sa.Column('events_json',sa.Text(),nullable=False),sa.Column('created_at',sa.DateTime(timezone=True),nullable=False),
            sa.Column('expires_at',sa.DateTime(timezone=True),nullable=False),sa.Column('updated_at',sa.DateTime(timezone=True),nullable=False),
            sa.CheckConstraint("state IN ('queued','provisioning','ready','failed','deleting','deleted')",name='ck_project_sandbox_state'),sa.CheckConstraint('slot IN (1,2)',name='ck_project_sandbox_slot'))


def downgrade():
    op.drop_table('project_sandbox')
    op.drop_table('project_automation_run')
    op.drop_table('project_automation_rule')
    op.drop_table('project_plan_scenario')
    op.drop_table('project_plan_allocation')
    op.drop_table('project_plan_team')
    op.drop_table('project_plan_node')
    op.drop_table('project_plan')
