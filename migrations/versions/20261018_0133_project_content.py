"""Project pages, intake forms, response snapshots and managed shortcuts."""
from alembic import op
import sqlalchemy as sa

revision='20261018_0133'
down_revision='20261018_0132'
branch_labels=None
depends_on=None
serviceops_migration_phase='expand'


def upgrade():
    existing=set(sa.inspect(op.get_bind()).get_table_names())
    if 'project_page' not in existing:
        op.create_table('project_page',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('tenant_id',sa.Integer(),sa.ForeignKey('tenant.id'),nullable=False,index=True),
            sa.Column('project_id', sa.Integer, sa.ForeignKey('project.id', ondelete='CASCADE'), nullable=False, index=True),
            sa.Column('title', sa.String(160), nullable=False),
            sa.Column('body', sa.Text, nullable=False),
            sa.Column('revision', sa.Integer, nullable=False),
            sa.Column('updated_by_id', sa.Integer, sa.ForeignKey('user.id'), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False))
    if 'project_form' not in existing:
        op.create_table('project_form',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('tenant_id',sa.Integer(),sa.ForeignKey('tenant.id'),nullable=False,index=True),
            sa.Column('project_id', sa.Integer, sa.ForeignKey('project.id', ondelete='CASCADE'), nullable=False, index=True),
            sa.Column('name', sa.String(100), nullable=False),
            sa.Column('description', sa.Text, nullable=False),
            sa.Column('config_json', sa.Text, nullable=False),
            sa.Column('enabled', sa.Boolean, nullable=False),
            sa.Column('revision', sa.Integer, nullable=False),
            sa.Column('updated_by_id', sa.Integer, sa.ForeignKey('user.id'), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))
    if 'project_form_response' not in existing:
        op.create_table('project_form_response',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('tenant_id',sa.Integer(),sa.ForeignKey('tenant.id'),nullable=False,index=True),
            sa.Column('form_id', sa.Integer, sa.ForeignKey('project_form.id', ondelete='SET NULL')),
            sa.Column('work_item_id', sa.Integer, sa.ForeignKey('work_item.id', ondelete='CASCADE'), nullable=False, index=True),
            sa.Column('name', sa.String(100), nullable=False),
            sa.Column('schema_json', sa.Text, nullable=False),
            sa.Column('answers_json', sa.Text, nullable=False),
            sa.Column('submitted_by_id', sa.Integer, sa.ForeignKey('user.id'), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))
    if 'project_shortcut' not in existing:
        op.create_table('project_shortcut',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('tenant_id',sa.Integer(),sa.ForeignKey('tenant.id'),nullable=False,index=True),
            sa.Column('project_id', sa.Integer, sa.ForeignKey('project.id', ondelete='CASCADE'), nullable=False, index=True),
            sa.Column('label', sa.String(80), nullable=False),
            sa.Column('url', sa.String(2000), nullable=False))


def downgrade():
    op.drop_table('project_shortcut')
    op.drop_table('project_form_response')
    op.drop_table('project_form')
    op.drop_table('project_page')
