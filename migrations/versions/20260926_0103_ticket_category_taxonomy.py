"""Admin-configurable ITIL v4/ServiceNow-style ticket category taxonomy.

Ticket.category/subcategory stay free text (unchanged) -- these two new tables
supply the controlled vocabulary the ticket form and AI drafting validate
against, replacing what used to be a hard-coded Python list
(`TICKET_CATEGORY_OPTIONS` in app.py). Every existing tenant is seeded with
today's six category names plus a starter set of ITIL v4/ServiceNow-style
subcategories, editable/removable by an administrator afterward.

Revision ID: 20260926_0103
Revises: 20260925_0102
"""
from alembic import op
import sqlalchemy as sa

revision = "20260926_0103"
down_revision = "20260925_0102"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

CATEGORIES = ["General", "Access", "Hardware", "Software", "Network", "Security"]
SUBCATEGORIES = {
    "General": ["General Inquiry", "How-To Question"],
    "Access": ["Account Lockout", "Password Reset", "Permission Request", "MFA / Authentication"],
    "Hardware": ["Laptop", "Desktop", "Printer", "Mobile Device", "Peripheral", "Server"],
    "Software": ["Application Issue", "Installation", "License", "Email & Collaboration", "Operating System"],
    "Network": ["Connectivity", "VPN", "Wireless", "DNS / DHCP", "Firewall"],
    "Security": ["Security Incident", "Vulnerability", "Policy Violation", "Phishing / Malware"],
}


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    # As with every other post-baseline migration that adds a table already
    # present in serviceops_models.py (e.g. 20260806_0063, 20260806_0060):
    # a fresh database already has these via the baseline migration.
    if not inspector.has_table("ticket_category"):
        op.create_table(
            "ticket_category",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(80), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.UniqueConstraint("tenant_id", "name", name="uq_ticket_category_tenant_name"),
        )
        op.create_index("ix_ticket_category_tenant_id", "ticket_category", ["tenant_id"])
    if not inspector.has_table("ticket_subcategory"):
        op.create_table(
            "ticket_subcategory",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("category_id", sa.Integer(), sa.ForeignKey("ticket_category.id"), nullable=False),
            sa.Column("name", sa.String(80), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("default_service_offering_id", sa.Integer(), sa.ForeignKey("service_offering.id")),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.UniqueConstraint("category_id", "name", name="uq_ticket_subcategory_category_name"),
        )
        op.create_index("ix_ticket_subcategory_tenant_id", "ticket_subcategory", ["tenant_id"])

    # Every existing tenant is seeded with today's six categories -- always run
    # (even on the fresh-DB path, where the tables above already existed),
    # idempotent via NOT EXISTS, matching the support_group/SysOps seeding
    # precedent in 20260806_0063. Administrators can rename/add/deactivate
    # every row afterward; this is starter data, not hard-coded behavior.
    for category in CATEGORIES:
        # op.execute() (unlike Connection.execute()) has no parameter-binding
        # support, so bind params through the connection directly.
        bind.execute(sa.text("""
            INSERT INTO ticket_category (name, active, tenant_id)
            SELECT CAST(:name AS VARCHAR(80)), true, tenant.id
            FROM tenant
            WHERE NOT EXISTS (
                SELECT 1 FROM ticket_category
                WHERE ticket_category.tenant_id = tenant.id AND lower(ticket_category.name) = lower(:name)
            )
        """), {"name": category})
        for subcategory in SUBCATEGORIES[category]:
            bind.execute(sa.text("""
                INSERT INTO ticket_subcategory (category_id, name, active, tenant_id)
                SELECT ticket_category.id, CAST(:sub AS VARCHAR(80)), true, ticket_category.tenant_id
                FROM ticket_category
                WHERE lower(ticket_category.name) = lower(:name)
                  AND NOT EXISTS (
                      SELECT 1 FROM ticket_subcategory
                      WHERE ticket_subcategory.category_id = ticket_category.id
                        AND lower(ticket_subcategory.name) = lower(:sub)
                  )
            """), {"name": category, "sub": subcategory})


def downgrade():
    # Unlike 20260920_0095's ai_run/ai_configuration (which stay empty until a
    # conversation actually happens, so a "refuse if populated" guard has a
    # real empty-table window), this migration's own upgrade unconditionally
    # seeds every tenant -- there is no window where these tables are new but
    # empty, so that guard would refuse every downgrade unconditionally,
    # including of *later* migrations rehearsing their own reversibility back
    # through this one. Reference/lookup data an administrator can freely
    # recreate (by re-running this migration or seed_itil()), so this follows
    # 20260806_0063's plain-drop precedent for new tables instead.
    op.drop_table("ticket_subcategory")
    op.drop_table("ticket_category")
