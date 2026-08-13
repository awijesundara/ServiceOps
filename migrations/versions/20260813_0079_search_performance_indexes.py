"""PostgreSQL trigram indexes for tenant-wide global search.

Revision ID: 20260813_0079
Revises: 20260812_0078
"""
from alembic import op


revision = "20260813_0079"
down_revision = "20260812_0078"
branch_labels = None
depends_on = None


SEARCH_INDEXES = {
    "ix_ticket_title_trgm": "ticket USING gin (title gin_trgm_ops)",
    "ix_ticket_description_trgm": "ticket USING gin (description gin_trgm_ops)",
    "ix_knowledge_title_trgm": "knowledge USING gin (title gin_trgm_ops)",
    "ix_knowledge_body_trgm": "knowledge USING gin (body gin_trgm_ops)",
    "ix_enterprise_record_title_trgm": "enterprise_record USING gin (title gin_trgm_ops)",
    "ix_enterprise_record_external_id_trgm": "enterprise_record USING gin (external_id gin_trgm_ops)",
    "ix_configuration_item_name_trgm": "configuration_item USING gin (name gin_trgm_ops)",
    "ix_configuration_item_serial_trgm": "configuration_item USING gin (serial_number gin_trgm_ops)",
    "ix_configuration_item_ip_trgm": "configuration_item USING gin (ip_address gin_trgm_ops)",
    "ix_configuration_item_model_trgm": "configuration_item USING gin (model gin_trgm_ops)",
    "ix_configuration_item_vendor_trgm": "configuration_item USING gin (vendor gin_trgm_ops)",
    "ix_configuration_item_location_trgm": "configuration_item USING gin (location gin_trgm_ops)",
    "ix_client_ticket_subject_trgm": "client_ticket USING gin (subject gin_trgm_ops)",
    "ix_client_ticket_description_trgm": "client_ticket USING gin (description gin_trgm_ops)",
    "ix_client_organization_name_trgm": "client_organization USING gin (name gin_trgm_ops)",
    "ix_client_organization_domain_trgm": "client_organization USING gin (domain gin_trgm_ops)",
    "ix_client_contact_name_trgm": "client_contact USING gin (name gin_trgm_ops)",
    "ix_client_contact_email_trgm": "client_contact USING gin (email gin_trgm_ops)",
}


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    for name, target in SEARCH_INDEXES.items():
        op.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {target}")


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for name in reversed(SEARCH_INDEXES):
        op.execute(f"DROP INDEX IF EXISTS {name}")
