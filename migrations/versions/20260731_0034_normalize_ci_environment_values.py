"""Normalize free-text environment values on existing ConfigurationItem rows
to their canonical label (e.g. "Prod" -> "Production", "UAT" -> "Staging"),
matching app.py's ENVIRONMENT_ALIASES. Without this, CIs imported before
environment normalization existed keep nonstandard values like "Prod" that
don't match "Production" in CCB_REQUIRED_ENVIRONMENTS comparisons or the
CMDB environment filter, silently skipping CCB approval on production
changes.

Revision ID: 20260731_0034
Revises: 20260731_0033
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0034"
down_revision = "20260731_0033"
branch_labels = None
depends_on = None

# Keep in sync with app.py's ENVIRONMENT_ALIASES.
ALIASES = {
    "prod": "Production", "production": "Production", "prd": "Production",
    "dev": "Development", "development": "Development",
    "uat": "Staging", "staging": "Staging", "stage": "Staging",
    "test": "Test", "qa": "Test",
}


def upgrade():
    bind = op.get_bind()
    if "configuration_item" not in sa.inspect(bind).get_table_names():
        return
    for raw_value, canonical in ALIASES.items():
        if raw_value == canonical.lower():
            continue
        bind.execute(
            sa.text(
                "UPDATE configuration_item SET environment = :canonical "
                "WHERE lower(environment) = :raw AND environment != :canonical"
            ),
            {"canonical": canonical, "raw": raw_value},
        )


def downgrade():
    pass
