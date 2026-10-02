"""Record which source last set each CMDB field, and clear literal "None".

field_sources maps a ConfigurationItem column name to the system that last
wrote it ("NetBox", "Snipe-IT", "Spreadsheet" or "Manual"), so one merged
CI can show where each value came from.

The CI edit form rendered an empty text field as the word "None", and
saving the form stored that word. Those values are cleared back to NULL.

Revision ID: 20261002_0108
Revises: 20260928_0107
"""
from alembic import op
import sqlalchemy as sa

revision = "20261002_0108"
down_revision = "20260928_0107"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

TEXT_COLUMNS = ("ip_address", "serial_number", "vendor", "model", "location", "cost_center", "description")


def upgrade():
    bind = op.get_bind()
    existing = {column["name"] for column in sa.inspect(bind).get_columns("configuration_item")}
    if "field_sources" not in existing:
        op.add_column("configuration_item", sa.Column(
            "field_sources", sa.JSON(), nullable=False, server_default=sa.text("'{}'"),
        ))
    for column in TEXT_COLUMNS:
        bind.execute(sa.text(f"UPDATE configuration_item SET {column} = NULL WHERE {column} = 'None'"))


def downgrade():
    with op.batch_alter_table("configuration_item") as batch:
        batch.drop_column("field_sources")
