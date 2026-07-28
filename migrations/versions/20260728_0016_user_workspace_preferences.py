"""Add governed user profile and interface preferences.

Revision ID: 20260728_0016
Revises: 20260728_0015
"""
from alembic import op
import sqlalchemy as sa

revision = "20260728_0016"
down_revision = "20260728_0015"
branch_labels = None
depends_on = None


def _add_missing(table, definitions):
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns(table)}
    with op.batch_alter_table(table) as batch:
        for name, column in definitions:
            if name not in columns:
                batch.add_column(column)


def upgrade():
    _add_missing("user", [
        ("title", sa.Column("title", sa.String(120), nullable=False, server_default="")),
        ("department", sa.Column("department", sa.String(120), nullable=False, server_default="")),
        ("business_phone", sa.Column("business_phone", sa.String(40), nullable=False, server_default="")),
        ("mobile_phone", sa.Column("mobile_phone", sa.String(40), nullable=False, server_default="")),
        ("timezone", sa.Column("timezone", sa.String(80), nullable=False, server_default="UTC")),
        ("date_format", sa.Column("date_format", sa.String(40), nullable=False, server_default="system")),
        ("calendar_integration", sa.Column("calendar_integration", sa.String(40), nullable=False, server_default="None")),
    ])
    _add_missing("user_preference", [
        ("accessible_tooltips", sa.Column("accessible_tooltips", sa.Boolean(), nullable=False, server_default=sa.true())),
        ("data_patterns", sa.Column("data_patterns", sa.Boolean(), nullable=False, server_default=sa.false())),
        ("compact_dates", sa.Column("compact_dates", sa.Boolean(), nullable=False, server_default=sa.false())),
        ("keyboard_shortcuts", sa.Column("keyboard_shortcuts", sa.Boolean(), nullable=False, server_default=sa.true())),
        ("date_time_display", sa.Column("date_time_display", sa.String(20), nullable=False, server_default="both")),
    ])


def downgrade():
    with op.batch_alter_table("user_preference") as batch:
        for name in ["date_time_display", "keyboard_shortcuts", "compact_dates", "data_patterns", "accessible_tooltips"]:
            batch.drop_column(name)
    with op.batch_alter_table("user") as batch:
        for name in ["calendar_integration", "date_format", "timezone", "mobile_phone", "business_phone", "department", "title"]:
            batch.drop_column(name)
