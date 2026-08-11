"""Client Management phase 2: custom field schema (ClientCustomFieldDefinition)
plus custom_fields JSON columns on ClientOrganization/ClientContact/ClientTicket,
and a settings JSON column on ClientOrganization for branding/notification
policy (phase 7).

Revision ID: 20260810_0068
Revises: 20260810_0067
"""
from alembic import op
import sqlalchemy as sa

revision = "20260810_0068"
down_revision = "20260810_0067"
branch_labels = None
depends_on = None

_JSON_COLUMNS = [
    ("client_organization", "settings"),
    ("client_organization", "custom_fields"),
    ("client_contact", "custom_fields"),
    ("client_ticket", "custom_fields"),
]


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    for table, column in _JSON_COLUMNS:
        columns = [c["name"] for c in inspector.get_columns(table)]
        if column not in columns:
            with op.batch_alter_table(table) as batch:
                batch.add_column(sa.Column(
                    column, sa.JSON(), nullable=False, server_default=sa.text("'{}'"),
                ))

    if not inspector.has_table("client_custom_field_definition"):
        op.create_table(
            "client_custom_field_definition",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("entity_type", sa.String(20), nullable=False),
            sa.Column("key", sa.String(60), nullable=False),
            sa.Column("label", sa.String(120), nullable=False),
            sa.Column("field_type", sa.String(20), nullable=False, server_default="text"),
            sa.Column("options_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("required", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint(
                "tenant_id", "entity_type", "key", name="uq_client_custom_field_tenant_entity_key",
            ),
        )
        op.create_index(
            "ix_client_custom_field_definition_tenant_id",
            "client_custom_field_definition", ["tenant_id"],
        )


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("client_custom_field_definition"):
        op.drop_table("client_custom_field_definition")
    for table, column in _JSON_COLUMNS:
        columns = [c["name"] for c in inspector.get_columns(table)]
        if column in columns:
            with op.batch_alter_table(table) as batch:
                batch.drop_column(column)
