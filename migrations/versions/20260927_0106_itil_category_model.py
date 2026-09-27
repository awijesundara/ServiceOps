"""Align every tenant's ticket categories with the adopted ITIL category model.

The model (serviceops-notes docs/ITIL_V5_CATEGORISATION.md) is a two-level
tree of nine top-level categories, categorised by the affected service or
CI, with at most about ten options per level. 20260926_0103 seeded a
different six-category starter set; this migration moves tenants still on
that starter set to the model without touching anything an administrator
created or renamed:

- "Access" and "Software" are relabelled to "Access / Identity" and
  "Software / Application" (one-to-one equivalents), together with the
  tickets that carry them, so reporting isn't split across both labels.
- Missing model categories and subcategories are added.
- Starter entries with no equivalent in the model (e.g. "General",
  "Mobile Device") are deactivated, never deleted: tickets keep their
  values and the form shows them as retired until recategorised.

Revision ID: 20260927_0106
Revises: 20260927_0105
"""
from alembic import op
import sqlalchemy as sa

revision = "20260927_0106"
down_revision = "20260927_0105"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

# Kept as a copy (a migration must never import app.py). Mirrors
# app.TICKET_CATEGORY_TAXONOMY at the time of writing.
MODEL = {
    "Hardware": ["Desktop", "Laptop", "Server", "Storage", "Peripheral"],
    "Software / Application": ["Business application", "OS", "Licensing", "Patching"],
    "Network": ["LAN", "WAN", "VPN", "DNS", "Firewall", "Wi-Fi"],
    "Access / Identity": ["Account creation", "Password reset", "Permissions", "MFA"],
    "Infrastructure / Platform": ["Compute", "Virtualisation", "Containers", "Cloud", "Backup"],
    "Security": ["Malware", "Phishing", "Vulnerability", "Policy breach"],
    "Data / Database": ["Availability", "Performance", "Corruption", "Restore"],
    "Communication": ["Email", "Telephony", "Collaboration tools"],
    "Facilities / Endpoint services": ["Printing", "Workplace equipment"],
}
RENAMES = {"Access": "Access / Identity", "Software": "Software / Application"}
# 20260926_0103's starter set, keyed by its original category name.
STARTER = {
    "General": ["General Inquiry", "How-To Question"],
    "Access": ["Account Lockout", "Password Reset", "Permission Request", "MFA / Authentication"],
    "Hardware": ["Laptop", "Desktop", "Printer", "Mobile Device", "Peripheral", "Server"],
    "Software": ["Application Issue", "Installation", "License", "Email & Collaboration", "Operating System"],
    "Network": ["Connectivity", "VPN", "Wireless", "DNS / DHCP", "Firewall"],
    "Security": ["Security Incident", "Vulnerability", "Policy Violation", "Phishing / Malware"],
}
TICKET_CATEGORY_COLUMNS = ("category", "closure_category")


def _in_model(category, subcategory):
    return subcategory.casefold() in {name.casefold() for name in MODEL.get(category, [])}


def upgrade():
    bind = op.get_bind()
    for old, new in RENAMES.items():
        # Per tenant, only where the target label doesn't already exist.
        tenants = bind.execute(sa.text("""
            SELECT c.tenant_id FROM ticket_category c
            WHERE c.name = :old AND NOT EXISTS (
                SELECT 1 FROM ticket_category t WHERE t.tenant_id = c.tenant_id AND lower(t.name) = lower(:new))
        """), {"old": old, "new": new}).scalars().all()
        for tenant_id in tenants:
            bind.execute(sa.text("UPDATE ticket_category SET name = :new WHERE tenant_id = :tenant AND name = :old"),
                         {"old": old, "new": new, "tenant": tenant_id})
            for column in TICKET_CATEGORY_COLUMNS:
                bind.execute(sa.text(f"UPDATE ticket SET {column} = :new WHERE tenant_id = :tenant AND {column} = :old"),
                             {"old": old, "new": new, "tenant": tenant_id})

    for category, subcategories in MODEL.items():
        bind.execute(sa.text("""
            INSERT INTO ticket_category (name, active, tenant_id)
            SELECT CAST(:name AS VARCHAR(80)), true, tenant.id FROM tenant
            WHERE NOT EXISTS (SELECT 1 FROM ticket_category c
                              WHERE c.tenant_id = tenant.id AND lower(c.name) = lower(:name))
        """), {"name": category})
        for subcategory in subcategories:
            bind.execute(sa.text("""
                INSERT INTO ticket_subcategory (category_id, name, active, tenant_id)
                SELECT c.id, CAST(:sub AS VARCHAR(80)), true, c.tenant_id FROM ticket_category c
                WHERE lower(c.name) = lower(:name) AND NOT EXISTS (
                    SELECT 1 FROM ticket_subcategory s WHERE s.category_id = c.id AND lower(s.name) = lower(:sub))
            """), {"name": category, "sub": subcategory})

    for starter_category, subcategories in STARTER.items():
        current = RENAMES.get(starter_category, starter_category)
        if current not in MODEL:
            bind.execute(sa.text("UPDATE ticket_category SET active = false WHERE name = :name"), {"name": current})
        for subcategory in subcategories:
            if _in_model(current, subcategory):
                continue
            bind.execute(sa.text("""
                UPDATE ticket_subcategory SET active = false
                WHERE name = :sub AND category_id IN (SELECT id FROM ticket_category WHERE name = :name)
            """), {"sub": subcategory, "name": current})


def downgrade():
    bind = op.get_bind()
    for starter_category, subcategories in STARTER.items():
        current = RENAMES.get(starter_category, starter_category)
        bind.execute(sa.text("UPDATE ticket_category SET active = true WHERE name = :name"), {"name": current})
        for subcategory in subcategories:
            bind.execute(sa.text("""
                UPDATE ticket_subcategory SET active = true
                WHERE name = :sub AND category_id IN (SELECT id FROM ticket_category WHERE name = :name)
            """), {"sub": subcategory, "name": current})

    for category, subcategories in MODEL.items():
        starter_names = {name.casefold() for name in STARTER.get(
            next((old for old, new in RENAMES.items() if new == category), category), [])}
        for subcategory in subcategories:
            if subcategory.casefold() in starter_names:
                continue
            bind.execute(sa.text("""
                DELETE FROM ticket_subcategory
                WHERE lower(name) = lower(:sub) AND category_id IN (SELECT id FROM ticket_category WHERE name = :name)
            """), {"sub": subcategory, "name": category})
        if category not in STARTER and category not in RENAMES.values():
            bind.execute(sa.text("""
                DELETE FROM ticket_category WHERE name = :name
                  AND NOT EXISTS (SELECT 1 FROM ticket_subcategory s WHERE s.category_id = ticket_category.id)
            """), {"name": category})

    for old, new in RENAMES.items():
        tenants = bind.execute(sa.text("""
            SELECT c.tenant_id FROM ticket_category c
            WHERE c.name = :new AND NOT EXISTS (
                SELECT 1 FROM ticket_category t WHERE t.tenant_id = c.tenant_id AND t.name = :old)
        """), {"old": old, "new": new}).scalars().all()
        for tenant_id in tenants:
            bind.execute(sa.text("UPDATE ticket_category SET name = :old WHERE tenant_id = :tenant AND name = :new"),
                         {"old": old, "new": new, "tenant": tenant_id})
            for column in TICKET_CATEGORY_COLUMNS:
                bind.execute(sa.text(f"UPDATE ticket SET {column} = :old WHERE tenant_id = :tenant AND {column} = :new"),
                             {"old": old, "new": new, "tenant": tenant_id})
