"""Allow team-owned services without requiring an individual owner.

Revision ID: 20261023_0143
Revises: 20261023_0142
"""
import logging
from alembic import op
import sqlalchemy as sa

revision = '20261023_0143'
down_revision = '20261023_0142'
branch_labels = None
depends_on = None
serviceops_migration_phase = 'contract'
serviceops_contract_after_version = '1.113.67'
logger = logging.getLogger(__name__)


def upgrade():
    try:
        columns = sa.inspect(op.get_bind()).get_columns('service_offering')
        if next(column for column in columns if column['name'] == 'owner_id')['nullable']:
            return
        with op.batch_alter_table('service_offering') as batch:
            batch.alter_column('owner_id', existing_type=sa.Integer(), nullable=True)
    except Exception as error:
        logger.error('Service team ownership migration failed (%s)', type(error).__name__)
        raise


def downgrade():
    try:
        bind = op.get_bind()
        if bind.execute(sa.text('SELECT 1 FROM service_offering WHERE owner_id IS NULL LIMIT 1')).first():
            raise RuntimeError('Cannot restore individual ownership while team-owned services have no person assigned')
        columns = sa.inspect(bind).get_columns('service_offering')
        if not next(column for column in columns if column['name'] == 'owner_id')['nullable']:
            return
        with op.batch_alter_table('service_offering') as batch:
            batch.alter_column('owner_id', existing_type=sa.Integer(), nullable=False)
    except Exception as error:
        logger.error('Service team ownership downgrade refused or failed (%s)', type(error).__name__)
        raise
