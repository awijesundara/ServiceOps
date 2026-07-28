"""Add enterprise incident record fields.

Revision ID: 20260728_0015
Revises: 20260728_0014
"""
from alembic import op
import sqlalchemy as sa

revision = "20260728_0015"
down_revision = "20260728_0014"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("ticket")}
    with op.batch_alter_table("ticket") as batch:
        if "subcategory" not in columns:
            batch.add_column(sa.Column(
                "subcategory", sa.String(80), nullable=False, server_default=""
            ))
        if "contact_type" not in columns:
            batch.add_column(sa.Column(
                "contact_type", sa.String(40), nullable=False,
                server_default="Self-service",
            ))
        if "notify" not in columns:
            batch.add_column(sa.Column(
                "notify", sa.String(40), nullable=False, server_default="Email"
            ))
        if "service_offering_id" not in columns:
            batch.add_column(sa.Column("service_offering_id", sa.Integer()))
            batch.create_foreign_key(
                "fk_ticket_service_offering", "service_offering",
                ["service_offering_id"], ["id"],
            )


def downgrade():
    with op.batch_alter_table("ticket") as batch:
        # Dropping the column removes its dependent foreign key on PostgreSQL.
        # SQLite batch migrations may not retain explicit constraint names, so
        # attempting to drop the constraint by name is not portable.
        batch.drop_column("service_offering_id")
        batch.drop_column("notify")
        batch.drop_column("contact_type")
        batch.drop_column("subcategory")
